sandbox-attacksurface-analysis-tools

(c) Google Inc. 2015, 2016, 2017
Developed by James Forshaw

This is a small suite of tools to test various properties of sandboxes on Windows. Many of the checking
tools take a -p flag which is used to specify the PID of a sandboxed process. The tool will impersonate
the token of that process and determine what access is allowed from that location. Also it's recommended
to run these tools as an administrator or local system to ensure the system can be appropriately enumerated.

CheckExeManifest: Check for specific executable manifest flags
CheckNetworkAccess: Check access to network stack
NewProcessFromToken: Create a new process based on existing token
TokenView: View and manipulate various process token values
NtApiDotNet: A basic managed library to access NT system calls and objects.
NtObjectManager: A powershell module which uses NtApiDotNet to expose the NT object manager

Note that the following tools are deprecated, they've been replaced with more flexible Powershell cmdlets.
You shouldn't use them as they've not even guaranteed to work correctly.

CheckDeviceAccess : Check access to device objects
CheckFileAccess: Check access to files
CheckObjectManagerAccess: Check access to object manager objects
CheckProcessAccess: Check access to processes
CheckResistryAccess: Check access to registry
ObjectList: Dump object manager namespace information
DumpTypeInfo: Dump simple kernel object type information
DumpProcessMitigations: Dump basic process mitigation details on Windows8+

The tools can be built with Visual Studio 2015

Release Notes:

1.1.1
-----
* Fix to native protected process creation.
* Added functions to create native NT processes.

1.1.0
-----
* Removed check tools, excluding CheckNetworkAccess.
* Added basic Job object cmdlets.
* Added creation of protected processes in Win32Process.
* Added service access checking cmdlet.
* Added get executable manifest cmdlet.

1.0.9
-----
* Made New-Win32Process more generic and added support for Win32k filter enable.
* Added function to capture token from a process using impersonation.
* Added basic support for Desktop and WindowStation objects using Win32u.dll exports.
* Added file locking implementation including async.
* Added hardlink enumeration.
* Added NTFS stream enumeration.
* Deprecated most of the old standalone utilities in favour of PS cmdlets.

1.0.8
-----
* Added cmdlets to create a kernel memory dump, system environment and licensing.
* Additional system calls implemented.
* Added access to secure boot policies and code integrity policies.
* Made Win32 Process creation more generic and added cmdlet.
* Added access check by type including SELF SID.

1.0.7
-----
* Added new cmdlets to do access checking. Many of the old standalone utilities are now deprecated.
* Added cmdlets to create lowbox tokens
* Added list of known capability SIDs and resolve them during name lookup
* Added cmdlet to get a SID
* Added cmdlet to do a standalone access checking
* Reworked the APIs to include non-throwing versions of many of the core Open/Create methods.
* Made NtType more inspectable, includes access enumeration and rationalizes the opening methods.
* Various additional properties such as extended process flags, checking for LPAC
* Rework of access mask handling. Now all low-level APIs use an AccessMask structure which has
  conversion operators to and from other enumerations.
* Various other bug fixes.

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
* Support getting and setting file EA buffer
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