/*!
    @file TestDriver.cpp

    @brief The basic test driver against DebugLogger.

    @author Satoshi Tanda

    @copyright Copyright (c) 2018, Satoshi Tanda. All rights reserved.
 */
#include <ntifs.h>

EXTERN_C DRIVER_INITIALIZE DriverEntry;

NTSTATUS
DriverEntry (
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
    )
{
    //
    // Test log messages and expected output.
    //
    PCSTR testLogLines[] =
    {
        "123",          // -> "123"
        "123\n",        // -> "123"
        "123\n ",       // -> "123"
                        // -> " "
        "123\r\n",      // -> "123"
        "12\n3",        // -> "12"
                        // -> "3"
        "12\n3\n",      // -> "12"
                        // -> "3"
        "12\n\n3",      // -> "12"
                        // -> "3"
    };

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    for (auto& line : testLogLines)
    {
        //
        // It will be logged despite that the level is INFO and not ERROR
        // because DebugLogger enters the system to the verbose mode.
        //
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "%s", line);
    }

    //
    // Always fail so this driver gets unloaded automatically.
    //
    return STATUS_UNSUCCESSFUL;
}