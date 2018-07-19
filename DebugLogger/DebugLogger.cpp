/*!
    @file DebugLogger.cpp

    @brief All C++ code of DebugLogger.

    @author Satoshi Tanda

    @copyright Copyright (c) 2018, Satoshi Tanda. All rights reserved.
 */
#include <fltKernel.h>
#include <ntstrsafe.h>

//
// Defines SYNCH_LEVEL for readability. SYNCH_LEVEL is 12 on both ARM64 and x64.
//
#ifndef SYNCH_LEVEL
#define SYNCH_LEVEL 12
#endif

//
// Handy macros to specify at which segment the code should be placed.
//
#define DEBUGLOGGER_INIT  __declspec(code_seg("INIT"))
#define DEBUGLOGGER_PAGED __declspec(code_seg("PAGE"))

//
// The size of log buffer in bytes. Two buffers of this size will be allocated.
// Change this as needed.
//
static const ULONG k_DebugLogBufferSize = PAGE_SIZE * 8;

//
// The log file path.
//
DECLARE_CONST_UNICODE_STRING(k_LogFilePath, L"\\SystemRoot\\DebugLogger.log");

//
// The pool tag.
//
static const ULONG k_PoolTag = 'LgbD';

//
// The maximum characters the DbgPrint family can handle at once.
//
static const ULONG k_MaxDbgPrintLogLength = 512;

//
// The format of a single debug log message stored in DEBUG_LOG_BUFFER::LogEntries.
//
#include <pshpack1.h>
typedef struct _DEBUG_LOG_ENTRY
{
    //
    // The system time of when this message is seen in the debug print callback.
    //
    LARGE_INTEGER Timestamp;

    //
    // The length of the message stored in LogLine in characters.
    //
    USHORT LogLineLength;

    //
    // The debug log message, not including terminating null, '\r' or '\n'.
    //
    CHAR LogLine[ANYSIZE_ARRAY];
} DEBUG_LOG_ENTRY, *PDEBUG_LOG_ENTRY;
static_assert(sizeof(DEBUG_LOG_ENTRY) == 11, "Must be packed for space");
#include <poppack.h>

//
// The active and inactive buffer layout.
//
typedef struct _DEBUG_LOG_BUFFER
{
    //
    // The pointer to the buffer storing the sequence of DEBUG_LOG_ENTRYs.
    //
    PDEBUG_LOG_ENTRY LogEntries;

    //
    // The offset to the address where the next DEBUG_LOG_ENTRY should be saved,
    // counted from LogEntries.
    //
    ULONG NextLogOffset;

    //
    // How many bytes are not save into LogEntries due to lack of space.
    //
    ULONG OverflowedLogSize;
} DEBUG_LOG_BUFFER, *PDEBUG_LOG_BUFFER;

//
// The structure used by the debug print callback.
//
typedef struct _PAIRED_DEBUG_LOG_BUFFER
{
    //
    // Indicates whether ActiveLogBuffer and InactiveLogBuffer are usable.
    //
    BOOLEAN BufferValid;

    //
    // The lock must be held before accessing any other fields of this structure.
    //
    EX_SPIN_LOCK ActiveLogBufferLock;

    //
    // The pointers to two buffers: active and inactive. Active buffer is used
    // by the debug print callback and to save new messages as they comes in.
    // Inactive buffer is buffer accessed and cleared up by the flush buffer thread.
    //
    PDEBUG_LOG_BUFFER ActiveLogBuffer;
    PDEBUG_LOG_BUFFER InactiveLogBuffer;
} PAIRED_DEBUG_LOG_BUFFER, *PPAIRED_DEBUG_LOG_BUFFER;

//
// The set of information the flush buffer thread may need.
//
typedef struct _FLUSH_BUFFER_THREAD_CONTEXT
{
    KEVENT ThreadExitEvent;
    PPAIRED_DEBUG_LOG_BUFFER PairedLogBuffer;
    HANDLE LogFileHandle;
    PKTHREAD FlushBufferThread;
    ULONG MaxOverflowedLogSize;
} FLUSH_BUFFER_THREAD_CONTEXT, *PFLUSH_BUFFER_THREAD_CONTEXT;

//
// Buffer structures as global variables. Initialized by StartDebugPrintCallback
// and cleaned up by StopDebugPrintCallback.
//
static DEBUG_LOG_BUFFER g_LogBuffer1;
static DEBUG_LOG_BUFFER g_LogBuffer2;
static PAIRED_DEBUG_LOG_BUFFER g_PairedLogBuffer;

//
// The thread context. Initialized by StartFlushBufferThread and cleaned up by
// StopFlushBufferThread.
//
static FLUSH_BUFFER_THREAD_CONTEXT g_ThreadContext;

//
// The space to save old debug filter states for all components. Used by
// EnableVerboseDebugOutput and DisableVerboseDebugOutput.
//
static ULONG g_DebugFilterStates[DPFLTR_ENDOFTABLE_ID];

//
// Code analysis wants this declaration.
//
DEBUGLOGGER_INIT EXTERN_C DRIVER_INITIALIZE DriverEntry;

/*!
    @brief Saves a single line debug message to the active buffer.

    @param[in] Timestamp - The time stamp of when the log message was sent.

    @param[in] LogLine - The single line, null-terminated debug log message.
        Does not include "\n".

    @param[in,out] PairedLogBuffer - Buffer to save the message.
*/
static
_IRQL_requires_(SYNCH_LEVEL)
VOID
SaveDebugOutputLine (
    _In_ const LARGE_INTEGER* Timestamp,
    _In_ PCCHAR LogLine,
    _Inout_ PPAIRED_DEBUG_LOG_BUFFER PairedLogBuffer
    )
{
    USHORT logLineLength;
    ULONG logEntrySize;
    BOOLEAN lockAcquired;
    PDEBUG_LOG_ENTRY logEntry;

    lockAcquired = FALSE;

    //
    // Get the length of the message in characters. The message should never be
    // an empty (as per behavior of strtok_s) and should never be longer than
    // what the DbgPrint family can handle.
    //
    logLineLength = static_cast<USHORT>(strlen(LogLine));
    if ((logLineLength == 0) || (logLineLength > k_MaxDbgPrintLogLength))
    {
        NT_ASSERT(FALSE);
        goto Exit;
    }

    //
    // Unlikely but one can output \r\n. Ignore this to normalize contents.
    //
    if (LogLine[logLineLength - 1] == '\r')
    {
        if ((--logLineLength) == 0)
        {
            goto Exit;
        }
    }

    logEntrySize = RTL_SIZEOF_THROUGH_FIELD(DEBUG_LOG_ENTRY, LogLineLength) +
        logLineLength;

    //
    // Acquire the lock to safely modify active buffer.
    //
    ExAcquireSpinLockExclusiveAtDpcLevel(&PairedLogBuffer->ActiveLogBufferLock);
    lockAcquired = TRUE;

    //
    // Bail out if a concurrent thread invalidated buffer.
    //
    if (PairedLogBuffer->BufferValid == FALSE)
    {
        goto Exit;
    }

    //
    // If the remaining buffer is not large enough to save this message, count
    // up the overflowed size and bail out.
    //
    if (PairedLogBuffer->ActiveLogBuffer->NextLogOffset + logEntrySize > k_DebugLogBufferSize)
    {
        PairedLogBuffer->ActiveLogBuffer->OverflowedLogSize += logEntrySize;
        goto Exit;
    }

    //
    // There are sufficient room to save the message. Get the address to save
    // the message within active buffer. On debug build, the address should be
    // filled with 0xff, indicating no one has yet touched there.
    //
    logEntry = reinterpret_cast<PDEBUG_LOG_ENTRY>(Add2Ptr(
                                PairedLogBuffer->ActiveLogBuffer->LogEntries,
                                PairedLogBuffer->ActiveLogBuffer->NextLogOffset));
    NT_ASSERT(logEntry->Timestamp.QuadPart == MAXULONG64);
    NT_ASSERT(logEntry->LogLineLength == MAXUSHORT);

    //
    // Save this message and update the offset to the address to save the next
    // message.
    //
    logEntry->Timestamp = *Timestamp;
    logEntry->LogLineLength = logLineLength;
    RtlCopyMemory(logEntry->LogLine, LogLine, logLineLength);
    PairedLogBuffer->ActiveLogBuffer->NextLogOffset += logEntrySize;

Exit:
    if (lockAcquired != FALSE)
    {
        ExReleaseSpinLockExclusiveFromDpcLevel(&PairedLogBuffer->ActiveLogBufferLock);
    }
    return;
}

/*!
    @brief Saves the debug log messages to active buffer.

    @param[in] Output - The formatted debug log message given to the API family.

    @param[in,out] PairedLogBuffer - Buffer to save the message.
*/
static
_IRQL_requires_(SYNCH_LEVEL)
VOID
SaveDebugOutput (
    _In_ const STRING* Output,
    _Inout_ PPAIRED_DEBUG_LOG_BUFFER PairedLogBuffer
    )
{
    CHAR ouputBuffer[k_MaxDbgPrintLogLength + 1];
    PCHAR strtokContext;
    PCHAR logLine;
    LARGE_INTEGER timestamp;

    //
    // Capture when the debug log message is sent.
    //
    KeQuerySystemTimePrecise(&timestamp);

    //
    // Ignore an empty message as it is not interesting.
    //
    if (Output->Length == 0)
    {
        goto Exit;
    }

    //
    // The message should be shorter than what the DbgPrint family can handle at
    // one call.
    //
    if (Output->Length > k_MaxDbgPrintLogLength)
    {
        NT_ASSERT(FALSE);
        goto Exit;
    }

    //
    // Copy the message as a null-terminated string.
    //
    RtlCopyMemory(ouputBuffer, Output->Buffer, Output->Length);
    ouputBuffer[Output->Length] = ANSI_NULL;

    //
    // Split it with \n and save each split message. Note that strtok_s removes
    // "\n\n", so empty lines are not saved.
    //
    strtokContext = nullptr;
    logLine = strtok_s(ouputBuffer, "\n", &strtokContext);
    while (logLine != nullptr)
    {
        SaveDebugOutputLine(&timestamp, logLine, PairedLogBuffer);
        logLine = strtok_s(nullptr, "\n", &strtokContext);
    }

Exit:
    return;
}

/*!
    @brief The callback routine for the DbgPrint family.

    @param[in] Output - The formatted debug log message given to the API family.

    @param[in] ComponentId - The ComponentId given to the API family.

    @param[in] Level - The Level given to the API family.
*/
static
_IRQL_requires_max_(SYNCH_LEVEL)
VOID
DebugPrintCallback (
    _In_ PSTRING Output,
    _In_ ULONG ComponentId,
    _In_ ULONG Level
    )
{
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(ComponentId);
    UNREFERENCED_PARAMETER(Level);

    //
    // IRQL is expected to be SYNCH_LEVEL already, but raise it to make sure
    // as an expected IRQL of this callback is not documented anywhere.
    //
    oldIrql = KeRaiseIrqlToSynchLevel();
    NT_ASSERT(oldIrql == SYNCH_LEVEL);

    //
    // Do actual stuff with context.
    //
    SaveDebugOutput(Output, &g_PairedLogBuffer);

    KeLowerIrql(oldIrql);
    return;
}

/*!
    @brief Disables verbose debug output by restoring filter states to original.
*/
DEBUGLOGGER_PAGED
static
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
DisableVerboseDebugOutput (
    VOID
    )
{
    ULONG states;
    BOOLEAN oldState;

    PAGED_CODE();

    for (ULONG componentId = 0; componentId < DPFLTR_ENDOFTABLE_ID; ++componentId)
    {
        states = g_DebugFilterStates[componentId];
        for (ULONG level = 0; level < 32; ++level)
        {
            //
            // Get the bit corresponding to the "level" from "states", and set
            // that bit as a new state (restore).
            //
            oldState = BooleanFlagOn(states, (1 << level));
            NT_VERIFY(NT_SUCCESS(DbgSetDebugFilterState(componentId, level, oldState)));
        }
    }

#if DBG
    //
    // Make sure that states of all components were reverted to the same states
    // as stored in g_DebugFilterStates.
    //
    for (ULONG componentId = 0; componentId < DPFLTR_ENDOFTABLE_ID; ++componentId)
    {
        states = 0;
        for (ULONG level = 0; level < 32; ++level)
        {
            oldState = static_cast<BOOLEAN>(DbgQueryDebugFilterState(componentId, level));
            SetFlag(states, (oldState << level));
        }
        NT_ASSERT(states == g_DebugFilterStates[componentId]);
    }
#endif
}

/*!
    @brief Stops the debug print callback and cleans up paired buffer.

    @param[in,out] PairedLogBuffer - The paired buffer associated to clean up.
*/
static
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
StopDebugPrintCallback (
    _Inout_ PPAIRED_DEBUG_LOG_BUFFER PairedLogBuffer
    )
{
    KIRQL oldIrql;

    //
    // Restore debug filters to the previous states.
    //
    DisableVerboseDebugOutput();

    //
    // Stop the callback.
    //
    NT_VERIFY(NT_SUCCESS(DbgSetDebugPrintCallback(DebugPrintCallback, FALSE)));

    //
    // Let us make sure no one is touching the paired buffer. Without this, it
    // is possible that the callback is still running concurrently on the other
    // processor and touching the paired buffer.
    //
    oldIrql = ExAcquireSpinLockExclusive(&PairedLogBuffer->ActiveLogBufferLock);

    //
    // Free both buffer and mark this paired buffer as invalid, so the other
    // thread waiting on this skin lock can tell the buffer is no longer valid
    // when the spin lock was released.
    //
    ExFreePoolWithTag(PairedLogBuffer->ActiveLogBuffer->LogEntries, k_PoolTag);
    ExFreePoolWithTag(PairedLogBuffer->InactiveLogBuffer->LogEntries, k_PoolTag);
    PairedLogBuffer->BufferValid = FALSE;

    ExReleaseSpinLockExclusive(&PairedLogBuffer->ActiveLogBufferLock, oldIrql);
}

/*!
    @brief Stops the flush buffer thread and cleans up the thread context.

    @param[in,out] ThreadContext - The context associated to the thread and to
        clean up.
*/
DEBUGLOGGER_PAGED
static
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
StopFlushBufferThread (
    _Inout_ PFLUSH_BUFFER_THREAD_CONTEXT ThreadContext
    )
{
    NTSTATUS status;

    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_INFO_LEVEL,
               "Stopping debug print logging.\n");

    if (ThreadContext->MaxOverflowedLogSize != 0)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   "Max overflow size = 0x%x. Consider increasing the buffer"
                   " size and recompile the driver for the next run.\n",
                   ThreadContext->MaxOverflowedLogSize);
    }

    //
    // Signal the event to exit the thread, and wait for termination.
    //
    (VOID)KeSetEvent(&ThreadContext->ThreadExitEvent, IO_NO_INCREMENT, FALSE);
    status = KeWaitForSingleObject(ThreadContext->FlushBufferThread,
                                   Executive,
                                   KernelMode,
                                   FALSE,
                                   nullptr);
    NT_ASSERT(status == STATUS_SUCCESS);
    ObDereferenceObject(ThreadContext->FlushBufferThread);

    //
    // No one should be touching the log file now. Close it.
    //
    NT_VERIFY(NT_SUCCESS(ZwClose(ThreadContext->LogFileHandle)));
}

/*!
    @brief Stops debug print logging.
*/
DEBUGLOGGER_PAGED
static
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
StopDebugPrintLoggging (
    VOID
    )
{
    PAGED_CODE();

    StopFlushBufferThread(&g_ThreadContext);
    StopDebugPrintCallback(&g_PairedLogBuffer);
}

/*!
    @brief Unloads this driver.

    @param[in] DriverObject - The associated driver object.
*/
DEBUGLOGGER_PAGED
static
_Function_class_(DRIVER_UNLOAD)
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
DriverUnload (
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);

    PAGED_CODE();

    StopDebugPrintLoggging();
}

/*!
    @brief Writes saved debug log messages into the log file and clears them.

    @details This function first swaps active buffer with inactive buffer, so
        that the currently active buffer can safely be accessed (ie, inactive
        buffer becomes active buffer). Then, writes contents of previously
        active buffer into the log file if contents exist. Then, updates the max
        overflow count as needed. Finally, it clears the contents of previously
        active buffer to make it ready to become active buffer again.

    @param[in,out] ThreadContext - Context to be used by the thread.
*/
static
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
FlushDebugLogEntries (
    _Inout_ PFLUSH_BUFFER_THREAD_CONTEXT ThreadContext
    )
{
    NTSTATUS status;
    PPAIRED_DEBUG_LOG_BUFFER pairedLogBuffer;
    KIRQL oldIrql;
    PDEBUG_LOG_BUFFER oldLogBuffer;
    IO_STATUS_BLOCK ioStatusBlock;

    status = STATUS_SUCCESS;
    pairedLogBuffer = ThreadContext->PairedLogBuffer;

    //
    // Swap active buffer and inactive buffer.
    //
    oldIrql = ExAcquireSpinLockExclusive(&pairedLogBuffer->ActiveLogBufferLock);
    oldLogBuffer = pairedLogBuffer->ActiveLogBuffer;
    pairedLogBuffer->ActiveLogBuffer = pairedLogBuffer->InactiveLogBuffer;
    pairedLogBuffer->InactiveLogBuffer = oldLogBuffer;
    ExReleaseSpinLockExclusive(&pairedLogBuffer->ActiveLogBufferLock, oldIrql);

    NT_ASSERT(pairedLogBuffer->ActiveLogBuffer != pairedLogBuffer->InactiveLogBuffer);

    //
    // Iterate all saved debug log messages (if exist).
    //
    for (ULONG offset = 0; offset < oldLogBuffer->NextLogOffset; /**/)
    {
        PDEBUG_LOG_ENTRY logEntry;
        CHAR writeBuffer[k_MaxDbgPrintLogLength + 50]; // 50 for date and time.
        ANSI_STRING tmpLogLine;
        TIME_FIELDS timeFields;
        LARGE_INTEGER localTime;

        logEntry = reinterpret_cast<PDEBUG_LOG_ENTRY>(Add2Ptr(
                                                    oldLogBuffer->LogEntries,
                                                    offset));

        //
        // Build a temporal ANSI_STRING for stringify non-null terminated string.
        //
        tmpLogLine.Buffer = logEntry->LogLine;
        tmpLogLine.Length = logEntry->LogLineLength;
        tmpLogLine.MaximumLength = logEntry->LogLineLength;

        //
        // Convert the time stamp to the local time in the human readable format.
        //
        ExSystemTimeToLocalTime(&logEntry->Timestamp, &localTime);
        RtlTimeToTimeFields(&localTime, &timeFields);

        status = RtlStringCchPrintfA(writeBuffer,
                                     RTL_NUMBER_OF(writeBuffer),
                                     "%02hd-%02hd %02hd:%02hd:%02hd.%03hd %Z\r\n",
                                     timeFields.Month,
                                     timeFields.Day,
                                     timeFields.Hour,
                                     timeFields.Minute,
                                     timeFields.Second,
                                     timeFields.Milliseconds,
                                     &tmpLogLine);
        if (!NT_SUCCESS(status))
        {
            //
            // This should not happen, but if it does, just discard all log
            // messages. The next attempt will very likely fail too.
            //
            NT_ASSERT(FALSE);
            break;
        }

        status = ZwWriteFile(ThreadContext->LogFileHandle,
                             nullptr,
                             nullptr,
                             nullptr,
                             &ioStatusBlock,
                             writeBuffer,
                             static_cast<ULONG>(strlen(writeBuffer)),
                             nullptr,
                             nullptr);
        if (!NT_SUCCESS(status))
        {
            //
            // This can happen when the system is shutting down and the file
            // system was already unmounted. Bail out, nothing we can do.
            //
            break;
        }

        //
        // Compute the offset to the next entry by adding the size of the current
        // entry.
        //
        offset += RTL_SIZEOF_THROUGH_FIELD(DEBUG_LOG_ENTRY, LogLineLength) +
            logEntry->LogLineLength;
    }

    //
    // If the debug log messages exist, and no error happened before, flush the
    // log file. This should not fail (unless the file system is unmounted
    // after the last successful write).
    //
    if ((oldLogBuffer->NextLogOffset != 0) && NT_SUCCESS(status))
    {
        status = ZwFlushBuffersFile(ThreadContext->LogFileHandle, &ioStatusBlock);
        NT_ASSERT(NT_SUCCESS(status));
    }

    //
    // Update the maximum overflow size as necessary.
    //
    ThreadContext->MaxOverflowedLogSize = max(ThreadContext->MaxOverflowedLogSize,
                                              oldLogBuffer->OverflowedLogSize);

    //
    // Finally, clear the previously active buffer.
    //
    oldLogBuffer->NextLogOffset = 0;
    oldLogBuffer->OverflowedLogSize = 0;
#if DBG
    RtlFillMemory(oldLogBuffer->LogEntries, k_DebugLogBufferSize, 0xff);
#endif
}

/*!
    @brief The entry point of the flush buffer thread.

    @param[in] Context - The thread context.
*/
DEBUGLOGGER_PAGED
static
_Function_class_(KSTART_ROUTINE)
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
FlushBufferThreadEntryPoint (
    _In_ PVOID Context
    )
{
    static const ULONG intervalMs = 500;
    NTSTATUS status;
    PFLUSH_BUFFER_THREAD_CONTEXT threadContext;
    LARGE_INTEGER interval;

    PAGED_CODE();

    threadContext = reinterpret_cast<PFLUSH_BUFFER_THREAD_CONTEXT>(Context);

    interval.QuadPart = -(10000ll * intervalMs);

    do
    {
        //
        // Flush log buffer with interval, or exit when it is requested.
        //
        status = KeWaitForSingleObject(&threadContext->ThreadExitEvent,
                                       Executive,
                                       KernelMode,
                                       FALSE,
                                       &interval);
        FlushDebugLogEntries(threadContext);
    } while (status == STATUS_TIMEOUT);

    //
    // It is probably a programming error if non STATUS_SUCCESS is returned. Let
    // us catch that.
    //
    NT_ASSERT(status == STATUS_SUCCESS);
    PsTerminateSystemThread(status);
}

/*!
    @brief Enables all levels of debug print for all components.

    @details This function enables all debug print while saving the previous
        state into g_DebugFilterStates for restore.
*/
DEBUGLOGGER_INIT
static
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
EnableVerboseDebugOutput (
    VOID
    )
{
    ULONG statesOfAllLevels;
    BOOLEAN state;

    PAGED_CODE();

    //
    // For all components.
    //
    for (ULONG componentId = 0; componentId < DPFLTR_ENDOFTABLE_ID; ++componentId)
    {
        //
        // For all levels (levels are 0-31) of the component.
        //
        statesOfAllLevels = 0;
        for (ULONG level = 0; level < 32; ++level)
        {
            //
            // Get the current state, and save it as a single bit onto the 32bit
            // integer (statesOfAllLevels).
            //
            state = static_cast<BOOLEAN>(DbgQueryDebugFilterState(componentId, level));
            SetFlag(statesOfAllLevels, (state << level));

            NT_VERIFY(NT_SUCCESS(DbgSetDebugFilterState(componentId, level, TRUE)));
        }
        g_DebugFilterStates[componentId] = statesOfAllLevels;
    }
}

/*!
    @brief Starts the debug print callback.

    @details This function takes two buffers to be initialized, and one paired
        buffer, which essentially references to those two buffers. All of them
        are initialized in this function.

    @param[out] LogBufferActive - Debug log buffer to use initially.

    @param[out] LogBufferInactive - Debug log buffer to be inactive initially.

    @param[out] PairedLogBuffer - A buffer pair to be used in the debug print
        callback.

    @return STATUS_SUCCESS or an appropriate status code.
*/
DEBUGLOGGER_INIT
static
_IRQL_requires_max_(PASSIVE_LEVEL)
_Check_return_
NTSTATUS
StartDebugPrintCallback (
    _Out_ PDEBUG_LOG_BUFFER LogBufferActive,
    _Out_ PDEBUG_LOG_BUFFER LogBufferInactive,
    _Out_ PPAIRED_DEBUG_LOG_BUFFER PairedLogBuffer
    )
{
    NTSTATUS status;
    PDEBUG_LOG_ENTRY logEntries1, logEntries2;

    PAGED_CODE();

    RtlZeroMemory(LogBufferActive, sizeof(*LogBufferActive));
    RtlZeroMemory(LogBufferInactive, sizeof(*LogBufferInactive));
    RtlZeroMemory(PairedLogBuffer, sizeof(*PairedLogBuffer));

    logEntries2 = nullptr;

    //
    // Allocate log buffers.
    //
    logEntries1 = reinterpret_cast<PDEBUG_LOG_ENTRY>(ExAllocatePoolWithTag(
                                                            NonPagedPoolNx,
                                                            k_DebugLogBufferSize,
                                                            k_PoolTag));
    if (logEntries1 == nullptr)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    logEntries2 = reinterpret_cast<PDEBUG_LOG_ENTRY>(ExAllocatePoolWithTag(
                                                            NonPagedPoolNx,
                                                            k_DebugLogBufferSize,
                                                            k_PoolTag));
    if (logEntries2 == nullptr)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

#if DBG
    //
    // Fill buffer contents with some distinguishable bytes for ease of debugging.
    //
    RtlFillMemory(logEntries1, k_DebugLogBufferSize, MAXUCHAR);
    RtlFillMemory(logEntries2, k_DebugLogBufferSize, MAXUCHAR);
#endif

    //
    // Initialize buffer variables, and mark the paired buffer as valid. This
    // lets the debug print callback use this paired buffer.
    //
    LogBufferActive->LogEntries = logEntries1;
    LogBufferInactive->LogEntries = logEntries2;
    PairedLogBuffer->ActiveLogBuffer = LogBufferActive;
    PairedLogBuffer->InactiveLogBuffer = LogBufferInactive;
    PairedLogBuffer->BufferValid = TRUE;

    //
    // We have set up everything the debug print callback needs. Start it.
    //
    status = DbgSetDebugPrintCallback(DebugPrintCallback, TRUE);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    //
    // All good. Enable all levels of debug print for all components.
    //
    EnableVerboseDebugOutput();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_INFO_LEVEL,
               "Starting debug print logging.\n");

Exit:
    if (!NT_SUCCESS(status))
    {
        if (logEntries2 != nullptr)
        {
            ExFreePoolWithTag(logEntries2, k_PoolTag);
        }
        if (logEntries1 != nullptr)
        {
            ExFreePoolWithTag(logEntries1, k_PoolTag);
        }
    }
    return status;
}

/*!
    @brief Starts the flush buffer thread.

    @param[out] ThreadContext - Context to be used by the thread.

    @return STATUS_SUCCESS or an appropriate status code.
*/
DEBUGLOGGER_INIT
static
_IRQL_requires_max_(PASSIVE_LEVEL)
_Check_return_
NTSTATUS
StartFlushBufferThread (
    _Out_ PFLUSH_BUFFER_THREAD_CONTEXT ThreadContext
    )
{
    static OBJECT_ATTRIBUTES attributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(
                                        &k_LogFilePath,
                                        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE);
    NTSTATUS status;
    HANDLE fileHandle;
    HANDLE threadHandle;
    IO_STATUS_BLOCK ioStatusBlock;
    PKTHREAD thread;

    PAGED_CODE();

    RtlZeroMemory(ThreadContext, sizeof(*ThreadContext));
    fileHandle = nullptr;

    //
    // Open or create the log file. Always append contents at the end.
    //
    status = ZwCreateFile(&fileHandle,
                          FILE_APPEND_DATA | SYNCHRONIZE,
                          &attributes,
                          &ioStatusBlock,
                          nullptr,
                          FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
                          FILE_OPEN_IF,
                          FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                          nullptr,
                          0);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    //
    // Initialize the context before creating the thread. This avoids race.
    //
    ThreadContext->LogFileHandle = fileHandle;
    ThreadContext->PairedLogBuffer = &g_PairedLogBuffer;
    KeInitializeEvent(&ThreadContext->ThreadExitEvent, SynchronizationEvent, FALSE);

    //
    // Create the thread with the ready-to-use context.
    //
    status = PsCreateSystemThread(&threadHandle,
                                  THREAD_ALL_ACCESS,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  FlushBufferThreadEntryPoint,
                                  ThreadContext);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    //
    // Get the created thread object. This code does not fail (even the kernel
    // code assumes so sometimes).
    //
    status = ObReferenceObjectByHandle(threadHandle,
                                       THREAD_ALL_ACCESS,
                                       *PsThreadType,
                                       KernelMode,
                                       reinterpret_cast<PVOID*>(&thread),
                                       nullptr);
    NT_VERIFY(NT_SUCCESS(ZwClose(threadHandle)));
    NT_ASSERT(NT_SUCCESS(status));

    //
    // FlushBufferThread is not referenced by the thread. So it is OK to
    // initialize after creation of the thread.
    //
    ThreadContext->FlushBufferThread = thread;

Exit:
    if (!NT_SUCCESS(status))
    {
        if (fileHandle != nullptr)
        {
            NT_VERIFY(NT_SUCCESS(ZwClose(fileHandle)));
        }
    }
    return status;
}

/*!
    @brief Starts debug print logging.

    @return STATUS_SUCCESS or an appropriate status code.
*/
DEBUGLOGGER_INIT
static
_IRQL_requires_max_(PASSIVE_LEVEL)
_Check_return_
NTSTATUS
StartDebugPrintLogging (
    VOID
    )
{
    NTSTATUS status;
    BOOLEAN callbackStarted;

    PAGED_CODE();

    callbackStarted = FALSE;

    //
    // Start debug print callback that saves debug print messages into one of
    // those two buffers.
    //
    status = StartDebugPrintCallback(&g_LogBuffer1, &g_LogBuffer2, &g_PairedLogBuffer);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    callbackStarted = TRUE;

    //
    // Starts the flush buffer thread that write the saved debug print
    // messages into a log file and clears the buffer.
    //
    status = StartFlushBufferThread(&g_ThreadContext);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

Exit:
    if (!NT_SUCCESS(status))
    {
        if (callbackStarted != FALSE)
        {
            StopDebugPrintCallback(&g_PairedLogBuffer);
        }
    }
    return status;
}

/*!
    @brief The entry point of the driver. Starts debug print logging.

    @param[in] DriverObject - The associated driver object.

    @param[in] RegistryPath - The associated registry path.

    @return STATUS_SUCCESS or an appropriate status code.
*/
DEBUGLOGGER_INIT
_Use_decl_annotations_
NTSTATUS
DriverEntry (
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    PAGED_CODE();

    DriverObject->DriverUnload = DriverUnload;

    //
    // Start debug print logging. This will fail when the driver started as Boot
    // start because we try to open or create the log file while the file system
    // is not mounted yet on that timing. Supporting that scenarios is pretty
    // easy though.
    //
    status = StartDebugPrintLogging();
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

Exit:
    return status;
}