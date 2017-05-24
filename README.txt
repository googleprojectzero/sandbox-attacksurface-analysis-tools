sandbox-attacksurface-analysis-tools

(c) Google Inc. 2015, 2016
Developed by James Forshaw

This is a small suite of tools to test various properties of sandboxes on Windows. Many of the checking
tools take a -p flag which is used to specify the PID of a sandboxed process. The tool will impersonate
the token of that process and determine what access is allowed from that location. Also it's recommended
to run these tools as an administrator or local system to ensure the system can be appropriately enumerated.

CheckDeviceAccess : Check access to device objects
CheckExeManifest: Check for specific executable manifest flags
CheckFileAccess: Check access to files
CheckObjectManagerAccess: Check access to object manager objects
CheckProcessAccess: Check access to processes
CheckResistryAccess: Check access to registry
CheckNetworkAccess: Check access to network stack
DumpTypeInfo: Dump simple kernel object type information
DumpProcessMitigations: Dump basic process mitigation details on Windows8+
NewProcessFromToken: Create a new process based on existing token
ObjectList: Dump object manager namespace information
TokenView: View and manipulate various process token values
NtApiDotNet: A basic managed library to access NT system calls and objects.
NtObjectManager: A powershell module which uses NtApiDotNet to expose the NT object manager

The tools can be built with Visual Studio 2015

Release Notes:

1.0.6
-----
* Added cmdlet to filter a Token object.
* Cleanups to various components to make them easier to use from PS

1.0.5
-----
* Added additional Known SIDs
* Unified the variant Get-NtToken* cmdlets into one.
* Added additional token cmdlets such as Logon and Clipboard.
* Added initial support for IO Completion Ports
* Added object creation time property
* Added support to set a process device map
* Added top level CanSynchronize property to NtObject
* Bugs fixes from Rustam Agametov
* Made process list in token viewer a list rather than a tree and made a separate handle tab.
1.0.4
-----
* Support getting and setting file EA buffe
* Added cmdlet to get NTSTATUS code information
* Support to toggle UIAccess and Virtualization flags on tokens
* Added asynchronous support for file operations using Task APIs
* Added support for virtual memory functions
* Added cmdlet to create named pipes and mailslots.
* Added support for specifying SD as SDDL directly to cmdlets.
* Added thread descriptions for Anniversary edition and above.

1.0.3
-----
* Fixed small bug in handling of IO_STATUS_BLOCK which could result in memory corruption.
* Added support to list directory entries for a file directory.
* Added support to do basic read and writes to a file.

1.0.2
-----
* Added support to disable dynamic code policy on a process.
* Added cmdlets for reparse points.
* Fixes for EA buffer.
* Added service SIDs.
* Added support for removing token privileges.
* Fixed token security attribute parsing.

v1.0.1
------
* Replaced all unmanaged code with a managed library.
* Added NtObjectManager Powershell Module

v1.0.0
------
* Initial Release