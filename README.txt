sandbox-attacksurface-analysis-tools

(c) Google Inc. 2015, 2016, 2017, 2018, 2019, 2020
Developed by James Forshaw

This is a small suite of PowerShell tools to test various properties of sandboxes on Windows. Many of the
tools take a -ProcessId flag which is used to specify the PID of a sandboxed process. The tool will impersonate
the token of that process and determine what access is allowed from that location. Also it's recommended
to run these tools as an administrator or local system to ensure the system can be appropriately enumerated.

EditSection: View and manipulate memory sections.
TokenView: View and manipulate various process token values.
NtApiDotNet: A basic managed library to access NT system calls and objects.
NtObjectManager: A powershell module which uses NtApiDotNet to expose the NT object manager.
ViewSecurityDescriptor: View the security descriptor from an SDDL string or an inherited object.

You can load the using the Import-Module Cmdlet. You'll need to disable signing requirements however.

For example copy the module to %USERPROFILE%\Documents\WindowsPowerShell\Modules then load the module with:

Import-Module NtObjectManager

You can now do things like listing the NT object manager namespace using:

Get-ChildItem NtObject:\

Also see help for various commons such as Get-NtProcess, Get-NtType or New-File.

The tools can be built with Visual Studio 2017. It's possible to also build NtApiDotNet and NtObjectManager
with .NET Core 2.0/PowerShell Core 6.0 by building the specific project files.

In order to build for PowerShell Core 6.0 you first need to build the .NET Framework
version of the module, or pull the latest version of NtObjectManager from the PowerShell
Gallery. Next build the .NET Core version of the module using the dotnet command line tool:

dotnet build NtObjectManager\NtObjectManager.Core.csproj -c Release

Now copy the files NtObjectManager.dll and NtApiDotNet.dll from the output folder to
the folder Core inside the original NtObjectManager module module directory.

Thanks to the people who were willing to test it and give feedback:
* Matt Graeber
* Lee Holmes
* Casey Smith
* Jared Atkinson

Release Notes:

1.1.28
--------
* Added Import-Win32Module and Get-Win32Module.
* Added support for Registry Keys in the NtObjectManager provider.
* Added Get-NtDirectoryEntry.
* Added Win32 CreateRemoteThread.
* Added addition Registry Key functions.
* Added Network Authentication commands.
* Added Authentication Token formatting commands.
* Added new filtering features to TokenViewer.
* Improved cmdlets for getting and setting object information classes.
* Added Add-NtSection and Remove-NtSection.
* Added Compare-NtObject.
* Added Test-NtTokenPrivilege.
* Added type parsing from PDBs via SymbolResolver.
* Added a summary format to Format-NtSecurityDescriptor.
* Added Out-HexDump.
* Added C# compiler support for .NET Core Support of Get-RpcClient.
* Updated New-NtSecurityDescriptor and Edit-NtSecurityDescriptor.
* Basic C++ NDR formatting from irsl@.
* Added Format-NtJob.
* Added New-NtSecurityAttribute and Get-NtAceConditionData.
* Added Device/User Claims to Token Viewer and Format-NtToken.
* Added many different commands to manipulate Security Descriptors.
* Added Win32 Security Descriptor commands.
* Added filtering for accessible path commands.
* Added Audit support.
* Added basic AuthZ API support.
* Added basic ASN.1 DER parsing and Format-ASN1DER command.
* Added Kerberos Keytab file reading and writing.

1.1.27
--------
* Added support for directory change notifications.
* Added New-NtDesktop, Get-NtDesktop and Get-NtDesktopName.
* Added New-NtWindowStation, Get-NtWindowStation and Get-NtWindowStationName.
* Changed Win32 error codes to an enumeration.
* Added Load/Unload driver.
* Added properties to NtType to show access masks.
* Added basic SendInput method.
* Added token source tab to Token Viewer.
* Updated for the Job object and New-NtJob.
* Added NtWindow class a HWND enumeration.
* Added Get-AccessibleWindowStation command.
* Added some well known WNF names.
* Added option to Get-AccessibleService to check file permissions.
* Added Set-NtProcessJob command.
* Added Get-AccessibleToken command.
* Added support for compound ACEs.
* Added Get/Sid-NtTokenSid and Get/Set-NtTokenGroup.
* Added Get-AccessibleEventTrace command.
* Added Get-AccessibleWnf command.

1.1.26
--------
* Add DeviceGuid to Get/New-NtFile
* Fixed bug in ETA registrations and added GUID enumeration.
* Added SetExceptionPort to NtProcess.
* Added child process mitigation improvements.
* Added extended Fork.
* Updated native process creation support.
* Various new non-throwing methods.
* Updated to C# 7.3.
* Added list of access rights to NtType.
* Added default mandatory policy to NtType.
* Added SetDisposition methods to NtFile.
* Added console and GUI support for Object ACEs.
* Updated access checking to support Object Types.
* Access check returns a structure rather than just an access mask.
* CPP style NDR formatting (#21)
* Added Get-NtTokenPrivilege command.
* Added Get-NtLocallyUniqueId command.

1.1.25
--------
* Added new options to Get-NtSecurityDescriptor.
* Updated accessible resource checking.
* Added Remove-NtTokenPrivilege.
* Added Session option to Get-NtToken.
* Added command line option to Show-NtToken.
* Added information classes for symbolic links.

1.1.24
--------
* Added Add-NtTokenSecurityAttribute and Remove-NtTokenSecurityAttribute cmdlets.
* Added additional properties for running servies.
* Added support for drivers to Get-RunningService and Get-AccesibleService.
* Added fake service NtType objects for services and SCM to allow formatting and the UI.
* Added NtType property to security descriptors.
* Added option to Show-NtToken to elevate to admin.
* Added Suspend, Resume and Stop process commands.
* Added Get-NtEaBuffer and Set-NtEaBuffer commands.
* Added open to Get-NtDebug to get from a process.

1.1.23
--------
* Added basic ETW APIs.
* Added new thread properties.
* Added Close-NtObject function.
* Added Get-AccessibleScheduledTask cmdlet.
* Added typing for New-ExecutionAlias and renamed to Set-ExecutionAlias.
* Added Compare-RpcServer.
* Fixed handling of FQBN token security attributes.
* Added option to Format-RpcClient to output to a directory.
* Added Select-RpcServer cmdlet.
* Added RPC ALPC port brute force.

1.1.22
--------
* Removed old standalone utilities, everything should be accessible from PowerShell.
* Added Test-NetworkAccess cmdlet to replace CheckNetworkAccess utility.
* Added Set-NtFileHardlink cmdlet.
* Various fixes for RPC client code.

1.1.21
--------
* Various updates to the NDR parser, including new types and support for correlation expressions.
* Added complete transaction cmdlets.
* Added extended process creation flags for Win32Process.
* Added Format-NtSecurityDescriptor to display on the console
* Added Copy-NtObject cmdlet.
* Added basic RPC ALPC client support.
* Added option to specify a debug object for a Win32 process.
* Added processor system information.

1.1.20
--------
* Added basic ALPC support including cmdlets.
* Added better debug support including cmdlets.
* Display container access rights in SD GUI and also extract SACL if available.
* Added Set/Get-NtProcessMitigation policy to get specific policies.
* Exposed process mitigation policies using flag enums.
* Added Win32.AppContainerProfile to create and delete AC profiles.
* Many new non-throwing methods added to objects.
* Added ReadScatter and WriteGather methods to NtFile.
* Improved formatting of IO Control Codes.
* Added ability to acknowledge oplock breaks.
* Added Wow64 FS redirection support.
* Use proper WIN32 NT status facility for Win32 errors as status codes.
* Added read/write to file from safe buffers.
* Added methods to zero or fill safe buffers using native methods.
* Fix bug with querying BnoIsolationPrefix which next took into account the enable flag correctly.
* Fix from diversenok "Improve detection of restricted tokens (#20)"
* Code cleanups and source code separation.

1.1.19
--------
* Fix for bug in NtWaitTimeout not creating infinite waits.
* Added some new NTSTATUS codes and break apart the status.
* Added some new FSCTL codes.

1.1.18.1
--------
* Added missing release notes.

1.1.18
------
* Added better support for transaction objects including some cmdlets.
* Added general QueryInformation and SetInformation methods to a number of objects.
* Added side channel isolation mitigation policy.
* Added more FS volume information classes.
* Added extended section/memory functions.
* Added a few missing NDR type formats.
* Added BNO isolation process attribute.
* Added new types to separate out named pipes from normal files.
* Added Start-NtFileOplock.
* Added support for absolute security descriptors.

1.1.17
------
* Added methods to get AppModel policy from a token.
* Added Start-Win32ChildProcess
* Default to a version of DbgHelp if installed to the NtObjectManager directory under x86 or x64.
* Added some setters to token properties.
* Added a fix for a memory corruption issue in getting NT type information on 32 bit platforms (from 1orenz0).
* Added option to parse out RPC clients in Get-RpcServer.
* Fixed performance issue with section viewer and the corrupter.
* Added a valid length property to NtMappedSection.
* Added Get-NtObjectFromHandle cmdlet.
* Added Copy-NtToken function.
* Added enumeration for device characteristics.
* Fixed path resolving for file paths.
* Added Get-RpcAlpcServer cmdlet.

1.1.16
------
* Added Get-NtFilePathType function.
* Added Add-NtSecurityDescriptorDaclAce function.
* Added Path support to Get-NtSecurityDescriptor and Set-NtSecurityDescriptor.
* Added parameter to only return a specific set of IIDs from a COM proxy definition.
* Added support for extracting RPC servers from a DLL.
* Added support for enumerating registered RPC endpoints with Get-RpcEndpoint.
* Added support for enumerating running service information with Get-RunningService.
* Added Get-NtAlpcServer function.
* Reworked OpenWithType to support bruteforce of the object type.
* Added Win32Utils method to parse command line and extract image path.
* Fix DepStatus On Windows Server 2K12 / 2K16 from Rosalie.
* Added option to Get-NtProcess and Get-NtThread to only return system information.
* Added basic transaction support to registry keys.

1.1.15
------
* Convert access exceptions during NDR parsing into an NdrParser exception rather than crashing the process.
* Added function to enumerate running services with PIDs.
* Added methods to load module into a symbol resolver after creation.
* Added basic support for WNF registrations including a Get-NtWnf cmdlet.
* Expose all parameters for section mapping.
* Added a Get-NtMappedSection cmdlet.
* Various fixes to NDR decoding.
* Added method to create an anonymous named pipe pair.
* Rework of cached signing level, including unpacked EA data based on information provided by Alex Ionescu.
* Added protection level to the base New-Win32Process function.
* Added access rights for process creation.

1.1.14
------
* Added basic support for transaction objects.
* Minor fixes for ALPC support.
* Implemented OOP NDR parsing.
* Added NDR parsing and formatting powershell functions such as New-NdrParser and Format-NdrComProxy
* Fix for display of NDR arrays from 1orenz0.
* Print NDR correlation descriptors during formatting.
* Added support to read out COM proxies.

1.1.13
------
* Fixed bug in Get-NtToken for sandboxed tokens.
* Extended support for Job objects.
* Added Set-NtFileReparsePoint cmdlet.
* Added support for viewing a file with Show-NtSection
* Added support for DuplicateTo methods from rosalie.lecart.
* Improved support for Win32 Desktop and WindowStation objects.
* ScriptBlock support for the $_ argument.
* Added SID -> Name cache to improve performance.
* Fixed user marshallers in NDR for Windows 7.
* Added internal security descriptor viewer control.

1.1.12
------
* Added basic NDR parser.
* Added basic symbol resolver.
* Added method to read a security descriptor from another process.
* Improved process memory read and writing methods.
* Added virtual memory cmdlets to allocate, release and modify memory.
* Added Get-EmbeddedAuthenticodeSignature function.
* Added Get and Set NtSecurityDescriptor functions.
* Added ProcessTrustLabel to basic security information set.
* Added Get-NtFileChild cmdlet.
* Added Get-NtKeyChild cmdlet.
* Added Get-NtDirectoryChild cmdlet.
* Added name lookup to NtIoControlCode.
* Added NtNamedPipeFile type with implementations of basic pipe functions.
* Added ADd-DosDevice and Remove-DosDevice cmdlets.
* Added file directory and stream visitors.
* Merged Get-NtLowBoxToken and Get-NtFilteredToken into Get-NtToken.
* Modified Show-NtSection to also display an arbitrary byte array.
* Added an Invoke-NtToken cmdlet to run a script block under impersonation.
* Added Remove-NtFile cmdlet.
* Added case sensitive property for RS4.
* Added flags for NtCreateDirectoryObjectEx.
* Added pseudo option to Get-NtToken.
* Improved conditional ACE support.

1.1.11
------
* Improved New-NtToken including adding missing IL
* Added new NTSTATUS codes from 1709
* Changes to native process creation
* Added OverrideChildProcessCreation for Win32 process
* Added display of process trust labels from tokens.
* Fixed IsChildProcessRestricted on 1709 and above (changed structure)
* Fixed named pipe server in TokenViewer
* Added -All parameter to Show-NtToken to display list of tokens.

1.1.10
------
* Added support for extended handle information to allow for PIDs > 64k.
* Added basic New-NtToken cmdlet and system call.
* Added Resolve-NtObjectAdddress cmdlet to resolve the addresses of a list of objects.
* Added generic object ReOpen method.
* Added vistor method to object directories to enumerate recursively with a callback.
* Added display of process trust labels.

1.1.9
-----
* Fix for bug when querying extended process information on Windows 7/8.
* Add OneDrive file attributes from thierry.franzetti.
* Added support for displaying child AppContainer names.
* Various improvements to section editor including integer data inspectors.

1.1.8
-----
* Better support for relative paths in the cmdlets including supporting ones based on the current directory.
* RenameEx and DispositionEx support from fllombard.
* Added Key value deletion and fixes from rsiestrunck.
* Fixed bug in NtOpenSession prototype.
* Added support for adding additional groups to a token in Get-NtToken if user has SeTcbPrivilege.
* Added Show-NtToken to display a token in the GUI, renamed old whois style token viewer to Show-NtTokenEffective.
* Added PowerShell functions to get and create execution alias reparse points.
* Added section viewer and editor with Show-NtSection function.

1.1.7
-----
* Added projects to build NtObjectManager for PowerShell Core 6.0
* Added additional techniques to open process tokens in access checking cmdlets.
* Fixed issues with Add-NtKey and added Remove-NtKey cmdlets.
* Minor fixes from fllombard
* Added change notify key with asynchronous support
* Added kernel LUID allocation

1.1.6
-----
* Added support for child process policy and desktop app policy to Win32ProcessConfig.
* Added new mitigation options from Win10 1709.
* Fix a couple of crashes.

1.1.5
-----
* Fixed crash on 32 bit Windows when enumerating NT types.
* Merged ManagedHandleUtils assembly into main NtApiDotNet under the Win32 namespace.

1.1.4
-----
* Added Show-NtSecurityDescriptor function.
* Added support for modifying security descriptors in the UI.
* Cleanup of access mask when being displayed in the UI.
* Added opaque reparse buffer.

1.1.3
-----
* Added Show-NtToken function.
* Added basic version checking for certain functions which can't be accessed on Windows 7.
* Fixed referenced System.Management.Automation assembly version to run properly with no PS2.
* Fixed some bugs in token structures which preventing being used with multiple values.
* Added support to Win32Process for LPAC.

1.1.2
-----
* Added Get-AccessibleHandle cmdlet.
* Support for oplock levels.
* Added support to set inherit and protect on close flags to objects.
* Added Get-NtFilePath function.

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