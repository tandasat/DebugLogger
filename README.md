DebugLogger
============

Introduction
-------------

DebugLogger is a software driver that lets you log kernel-mode debug output into
a file on Windows. DebugLogger can be understood as an open source implementation
of [Sysinternals DebugView](https://docs.microsoft.com/en-us/sysinternals/downloads/debugview)
with limited functionality.


Motivation
-----------

Monitoring debug output is one of the most essential tasks for developing and
debugging device drivers on Windows. Developers can easily do this by either
attaching a kernel-debugger to the target system or using DebugView, which allows
developers to view debug output without attaching a kernel-debugger.

Unfortunately, neither is an option when:
  - your target system cannot run DebugView and does not have a necessary
    interface to physically attach a kernel-debugger
  - and, a virtual machine as a target system is unavailable

The primary example of this situation is ARM64. I, for example, have an
[ASUS NovaGo TP370QL](https://www.asus.com/ca-en/2-in-1-PCs/ASUS-NovaGo-TP370QL/)
running Windows 10 on ARM64 processors, and it does not have an interface to
attach a kernel-debugger. Also, neither DebugView nor any virtualization solution
I am familiar with supports Windows on ARM64 processors.

I was also under the exact same circumstance when I was developing a device driver
for Windows RT, which ran on ARM processors. I ended up with writing a file-based
logger to circumvent the issue, but it was not trivial and necessary work essentially.

Having an open source implementation of DebugView-like tools allows developers to
participate in developing device drivers for such uncommon platforms more easily.


Comparison
-----------

To clarify what DebugLogger can and cannot do, here is a brief comparison of
DebugLogger and DebugView.

|                                            | DebugLogger | DebugView    |
|--------------------------------------------|-------------|--------------|
| kernel-mode debug output monitoring        | YES         | YES          |
| Save debug output to a file                | ALWAYS      | YES          |
| Enabling verbose kernel output             | ALWAYS      | YES          |
| User-mode debug output monitoring          | NO          | YES          |
| Boot time monitoring                       | NO          | YES          |
| Remote-system monitoring                   | NO          | YES          |
| Debug output inclusion / exclusion filters | NO          | YES          |
| Support of x86 Windows                     | NO          | YES          |
| Support of Windows 7 and older             | NO          | YES          |
| Support of x64 Windows 10                  | YES         | NO BUT WORKS |
| Support of ARM64 Windows                   | YES         | NO           |
| Open source                                | YES         | NO           |


Usage
------

To the pre-compiled file **for ARM64**, goto
[Releases](https://github.com/tandasat/DebugLogger/releases) and download the
latest release.

To build DebugLogger from source code, clone full source code from Github with
the below command and compile it on a supported version of Visual Studio.

    $ git clone https://github.com/tandasat/DebugLogger.git

You have to enable test signing to install the driver before installing it. To
do that, open the command prompt with the administrator privilege and run the
following command, and then restart the system to activate the change:

    >bcdedit /set testsigning on

To install and uninstall the DebugLogger driver, use the `sc` command. For
installation and start:

    >sc create DebugLogger type= kernel binPath= C:\Users\user\Desktop\DebugLogger.sys
    >sc start DebugLogger

For uninstallation:

    >sc stop DebugLogger
    >sc delete DebugLogger
    >bcdedit /deletevalue testsigning


Output
-------

All captured debug output are saved in `C:\Windows\DebugLogger.log`.

Any `tail -f` like command lets you view contents of this file real-time and
gives similar user experience as DebugView does. The below command does this:

    > powershell Get-Content -Path C:\Windows\DebugLogger.log -Wait

Here is an example output from Process Hacker's KProcessHacker3 driver on the
ARM64 system.
![ExampleWithProcessHacker](/Images/ExampleWithProcessHacker.jpg)

For the testing purpose, the test driver `TestDriver` is included in the project.
Install and run this driver using the `sc` command to see output.


Supported Platforms
--------------------
- Visual Studio 2017 Preview (15.8 Preview 1 or later)
  - You will need additional Visual Studio components to compile device drivers
    for ARM64 processors. See [Building ARM64 Drivers with the WDK](
    https://docs.microsoft.com/en-us/windows-hardware/drivers/develop/building-arm64-drivers) for more information.
- 64bit versions of Windows 10 on ARM64 or x64
