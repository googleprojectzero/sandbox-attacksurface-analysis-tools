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
ModuleVersion = '1.1.26'

# ID used to uniquely identify this module
GUID = 'ac251c97-67a6-4bc4-bb8a-5ae300e93030'

# Author of this module
Author = 'James Forshaw'

# Company or vendor of this module
CompanyName = 'Google Inc.'

# Copyright statement for this module
Copyright = '(c) 2016-2020 Google Inc. All rights reserved.'

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
          'Import-NtObject', 'Export-NtObject', 'Get-ExecutionAlias', 'Set-ExecutionAlias', 'Set-ExecutionAlias', 'Show-NtToken', 'Show-NtSection',
          'Resolve-NtObjectAddress', 'Invoke-NtToken', 'Get-NtSecurityDescriptor',
          'Set-NtSecurityDescriptor', 'Add-NtVirtualMemory', 'Get-NtVirtualMemory', 'Remove-NtVirtualMemory', 'Set-NtVirtualMemory',
          'Read-NtVirtualMemory', 'Write-NtVirtualMemory', 'Get-EmbeddedAuthenticodeSignature', 'Get-NtSidName', 'New-SymbolResolver', 
          'New-NdrParser', 'Format-NdrComplexType', 'Format-NdrProcedure', 'Format-NdrComProxy', 'Get-NdrComProxy', 'Get-NdrRpcServerInterface',
          'Format-NdrRpcServerInterface', 'Get-NtMappedSection', 'Get-NtWnf', 'Get-NtCachedSigningLevel', 'Add-NtSecurityDescriptorDaclAce',
          'Get-NtFilePathType', 'New-NtType', 'Get-NtAlpcServer', 'Get-RpcEndpoint', 'Get-RpcServer', 'Set-GlobalSymbolResolver',
          'Get-RunningService', 'Copy-NtToken', 'Get-RpcAlpcServer', 'Get-NtObjectFromHandle', 'Start-Win32ChildProcess', 'Get-NtKeyValue',
          'Start-NtFileOplock', 'Format-RpcServer', 'Get-NtObjectInformation', 'Set-NtObjectInformation', 'Get-NtProcessMitigationPolicy',
          'Set-NtProcessMitigationPolicy', 'Format-NtSecurityDescriptor', 'Get-AppContainerProfile', 'New-AppContainerProfile',
          'Get-RpcClient', 'Format-RpcClient', 'Set-RpcServer', 'Connect-RpcClient', 'New-RpcContextHandle', 'Format-RpcComplexType',
          'Get-Win32File', 'Close-NtObject', 'Start-AccessibleScheduledTask', 'Get-NtEaBuffer', 'Set-NtEaBuffer',
          'Suspend-NtProcess', 'Resume-NtProcess', 'Stop-NtProcess', 'Suspend-NtThread', 'Resume-NtThread', 'Stop-NtThread',
          'Format-NtToken', 'Remove-NtTokenPrivilege', 'Get-NtTokenPrivilege', 'Get-NtLocallyUniqueId', 'Get-NtTokenGroup'

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
               'Remove-DosDevice', 'Get-NtFileChild', 'Set-NtFileReparsePoint',
               'Get-NtPartition', 'New-NtPartition', 'Get-NtWaitTimeout', 'New-NtTransaction', 
               'Get-NtTransaction', 'New-NtTransactionManager', 'Get-NtTransactionManager',
               'Connect-NtAlpcClient', 'New-NtAlpcServer', 'New-NtAlpcPortAttributes',
               'New-NtAlpcMessage', 'Send-NtAlpcMessage', 'Receive-NtAlpcMessage',
               'Connect-NtAlpcServer', 'New-NtAlpcReceiveAttributes', 'New-NtAlpcSendAttributes',
               'New-NtAlpcPortSection', 'New-NtAlpcDataView', 'New-NtAlpcSecurityContext',
               'New-NtDebug', 'Get-NtDebug', 'Start-NtDebugWait', 'Add-NtDebugProcess',
               'Remove-NtDebugProcess', 'Copy-NtObject', 'New-NtResourceManager',
               'Get-NtResourceManager', 'Get-NtTransactionGuid', 'Get-NtEnlistment',
               'New-NtEnlistment', 'Get-RpcServerName', 'Set-RpcServerName',
               'Set-NtFileHardlink', 'Test-NetworkAccess', 'Get-AccessibleScheduledTask',
               'Compare-RpcServer', 'Select-RpcServer', 'Add-NtTokenSecurityAttribute',
               'Remove-NtTokenSecurityAttribute'

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
        ProjectUri = 'https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools'

        # ReleaseNotes of this module
        ReleaseNotes = '1.1.26
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
'

        # External dependent modules of this module
        # ExternalModuleDependencies = ''

    } # End of PSData hashtable
    
 } # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

