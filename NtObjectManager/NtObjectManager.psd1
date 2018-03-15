#  Copyright 2016 Google Inc. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

@{

# Script module or binary module file associated with this manifest.
RootModule = 'NtObjectManager.psm1'

# Version number of this module.
ModuleVersion = '1.1.11'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = 'ac251c97-67a6-4bc4-bb8a-5ae300e93030'

# Author of this module
Author = 'James Forshaw'

# Company or vendor of this module
CompanyName = 'Google Inc.'

# Copyright statement for this module
Copyright = '(c) 2016, 2017, 2018 Google Inc. All rights reserved.'

# Description of the functionality provided by this module
Description = 'This module adds a provider and cmdlets to access the NT object manager namespace.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '3.0'

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
DotNetFrameworkVersion = '4.5'

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
CLRVersion = '4.0'

# Format files (.ps1xml) to be loaded when importing this module
FormatsToProcess = 'Formatters.ps1xml'

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = 'Get-AccessibleAlpcPort', 'Set-NtTokenPrivilege',
          'Set-NtTokenIntegrityLevel', 'Get-NtProcessMitigations', 'New-NtKernelCrashDump', 'New-NtObjectAttributes',
          'New-NtSecurityQualityOfService', 'Get-NtLicenseValue', 'Get-NtSystemEnvironmentValue', 'New-Win32Process',
          'New-NtEaBuffer', 'New-NtSectionImage', 'New-Win32ProcessConfig', 'Get-NtTokenFromProcess', 'Get-ExecutableManifest',
          'New-NtProcess', 'New-NtProcessConfig', 'Get-NtFilePath', 'Show-NtTokenEffective', 'Show-NtSecurityDescriptor', 'Get-NtIoControlCode',
          'Import-NtObject', 'Export-NtObject', 'Get-ExecutionAlias', 'New-ExecutionAlias', 'Show-NtToken', 'Show-NtSection',
          'Resolve-NtObjectAddress', 'Invoke-NtToken', 'Get-NtFilteredToken', 'Get-NtLowBoxToken', 'Get-NtSecurityDescriptor',
          'Set-NtSecurityDescriptor', 'Add-NtVirtualMemory', 'Get-NtVirtualMemory', 'Remove-NtVirtualMemory', 'Set-NtVirtualMemory',
          'Read-NtVirtualMemory', 'Write-NtVirtualMemory', 'Get-EmbeddedAuthenticodeSignature'

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = 'Add-NtKey', 'Get-NtDirectory', 'Get-NtEvent', 'Get-NtFile', 
               'Get-NtFileReparsePoint', 'Get-NtHandle', 'Get-NtKey', 'Get-NtMutant', 
               'Get-NtNamedPipeFile', 'Get-NtObject', 'Get-NtProcess', 
               'Get-NtSemaphore', 'Get-NtStatus', 'Get-NtSymbolicLink', 
               'Get-NtSymbolicLinkTarget', 'Get-NtThread', 'Get-NtToken', 'Get-NtType', 
               'New-NtDirectory', 'New-NtEvent', 'New-NtFile', 'New-NtKey', 
               'New-NtMailslotFile', 'New-NtMutant', 'New-NtNamedPipeFile', 
               'New-NtSecurityDescriptor', 'New-NtSemaphore', 'New-NtSymbolicLink', 
               'Remove-NtFileReparsePoint', 'Start-NtWait', 'Use-NtObject',
               'Get-NtSid', 'Get-NtSection', 'New-NtSection', 'Get-AccessibleAlpcPort',
               'Get-AccessibleKey', 'Get-AccessibleProcess', 'Get-AccessibleFile',
               'Get-AccessibleObject', 'Get-NtAccessMask', 'Get-AccessibleDevice',
               'Get-AccessibleNamedPipe', 'Get-NtGrantedAccess', 'Get-NtJob', 'New-NtJob',
               'Get-AccessibleService', 'Get-AccessibleHandle', 'Remove-NtKey', 'New-NtToken',
               'Remove-NtFile', 'Get-NtDirectoryChild', 'Get-NtKeyChild', 'Add-DosDevice', 
               'Remove-DosDevice', 'Get-NtFileChild'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = 'security','defence','offence','sandbox'

        # A URL to the license for this module.
        LicenseUri = 'http://www.apache.org/licenses/LICENSE-2.0.html'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/google/sandbox-attacksurface-analysis-tools'

        # ReleaseNotes of this module
        ReleaseNotes = '1.1.11
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
* Fix a couple of crashes.1.1.5
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
* Added basic version checking for certain functions which can''t be accessed on Windows 7.
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
1.0.1
-----
* Fixed bug in Get-NtThread with -ProcessId
* Added support for FilterScript for Get-NtThread
* Added support for querying thread dynamic code opt-out policy
* Added support for RFG mitigation
1.0.0
-----
Initial release:
* NT Object Manager drive provider
* Cmdlets to directory work with Directorys, Files, Symbolic Links, Events, Semaphores, Processes, Threads, Tokens etc.'

        # External dependent modules of this module
        # ExternalModuleDependencies = ''

    } # End of PSData hashtable
    
 } # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

