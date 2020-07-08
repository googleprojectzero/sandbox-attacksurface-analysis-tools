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
ModuleVersion = '1.1.28'

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
          'Resolve-NtObjectAddress', 'Get-NtSecurityDescriptor', 'Get-NtSecurityDescriptorIntegrityLevel',
          'Set-NtSecurityDescriptor', 'Add-NtVirtualMemory', 'Get-NtVirtualMemory', 'Remove-NtVirtualMemory', 'Set-NtVirtualMemory',
          'Read-NtVirtualMemory', 'Write-NtVirtualMemory', 'Get-EmbeddedAuthenticodeSignature', 'Get-NtSidName', 'New-SymbolResolver', 
          'New-NdrParser', 'Format-NdrComplexType', 'Format-NdrProcedure', 'Format-NdrComProxy', 'Get-NdrComProxy', 'Get-NdrRpcServerInterface',
          'Format-NdrRpcServerInterface', 'Get-NtMappedSection', 'Get-NtWnf', 'Get-NtCachedSigningLevel', 'Add-NtSecurityDescriptorDaclAce',
          'Get-NtFilePathType', 'New-NtType', 'Get-NtAlpcServer', 'Get-RpcEndpoint', 'Get-RpcServer', 'Set-GlobalSymbolResolver',
          'Get-RunningService', 'Copy-NtToken', 'Get-RpcAlpcServer', 'Get-NtObjectFromHandle', 'Start-Win32ChildProcess', 'Get-NtKeyValue',
          'Start-NtFileOplock', 'Format-RpcServer', 'Get-NtProcessMitigationPolicy',
          'Set-NtProcessMitigationPolicy', 'Format-NtSecurityDescriptor', 'Get-AppContainerProfile', 'New-AppContainerProfile',
          'Get-RpcClient', 'Format-RpcClient', 'Set-RpcServer', 'Connect-RpcClient', 'New-RpcContextHandle', 'Format-RpcComplexType',
          'Get-Win32File', 'Close-NtObject', 'Start-AccessibleScheduledTask', 'Get-NtEaBuffer', 'Set-NtEaBuffer',
          'Suspend-NtProcess', 'Resume-NtProcess', 'Stop-NtProcess', 'Suspend-NtThread', 'Resume-NtThread', 'Stop-NtThread',
          'Format-NtToken', 'Remove-NtTokenPrivilege', 'Get-NtTokenPrivilege', 'Get-NtLocallyUniqueId', 'Get-NtTokenGroup',
          'Get-NtTokenSid', 'Set-NtTokenSid', 'Set-NtTokenGroup', 'Get-NtDesktopName', 'Get-NtWindowStationName',
          'Get-NtWindow', 'Out-HexDump', 'Get-NtTypeAccess', 'Get-NtAtom', 'Add-NtAtom', 'Remove-NtAtom',
          'Import-Win32Module', 'Get-Win32Module', 'Get-Win32ModuleExport', 'Get-Win32ModuleImport', 'Get-NtDirectoryEntry',
          'Remove-NtKeyValue', 'Read-AuthCredential', 'Get-AuthPackage', 'Get-AuthCredentialHandle', 'Get-AuthServerContext',
          'Get-AuthClientContext', 'Update-AuthServerContext', 'Update-AuthClientContext', 'Get-AuthAccessToken', 'Get-NtKernelModule',
          'Get-NtObjectInformationClass', 'Add-NtSection', 'Remove-NtSection', 'Compare-NtObject', 'Edit-NtSecurityDescriptor',
          'Set-NtSecurityDescriptorOwner', 'Set-NtSecurityDescriptorGroup', 'Set-NtSecurityDescriptorIntegrityLevel',
          'ConvertFrom-NtAceCondition', 'ConvertFrom-NtSecurityDescriptor', 'Remove-NtSecurityDescriptorOwner',
          'Remove-NtSecurityDescriptorGroup', 'New-NtUserGroup', 'New-NtAcl', 'Set-NtSecurityDescriptorDacl',
          'Set-NtSecurityDescriptorSacl', 'Copy-NtSecurityDescriptor', 'Test-NtSecurityDescriptor',
          'Get-NtSecurityDescriptorOwner', 'Get-NtSecurityDescriptorGroup', 'Get-NtSecurityDescriptorDacl',
          'Get-NtSecurityDescriptorSacl', 'Set-NtSecurityDescriptorControl', 'Get-NtSecurityDescriptorControl',
          'Remove-NtSecurityDescriptorDacl', 'Remove-NtSecurityDescriptorSacl', 'Remove-NtSecurityDescriptorIntegrityLevel',
          'Add-NtSecurityDescriptorControl', 'Remove-NtSecurityDescriptorControl', 'Format-Win32SecurityDescriptor',
          'New-ObjectTypeTree', 'Add-ObjectTypeTree', 'ConvertTo-NtAceCondition', 'Get-NtTokenMandatoryPolicy',
          'Clear-NtSecurityDescriptorDacl', 'Clear-NtSecurityDescriptorSacl', 'Get-CentralAccessPolicy',
          'Remove-ObjectTypeTree', 'Set-ObjectTypeTreeAccess', 'Revoke-ObjectTypeTreeAccess', 'Select-ObjectTypeTree',
          'Test-NtObject', 'Get-NtTokenIntegrityLevel', 'Get-NtAuditPolicy', 'Set-NtAuditPolicy', 'Get-NtAuditSecurity',
          'Set-NtAuditSecurity', 'Format-AuthToken', 'Get-AuthToken', 'Test-AuthContext', 'Get-NtLogonSession',
          'Get-NtAccountRight', 'Get-NtAccountRightSid', 'Get-NtConsoleSession', 'Get-ServicePrincipalName',
          'Get-NtTokenId', 'Get-AuthCredential', 'Export-AuthToken', 'Import-AuthToken', 'Get-MD4Hash',
          'Format-ASN1DER', 'Import-KerberosKeyTab', 'Export-KerberosKeyTab', 'New-KerberosKey', 'Get-KerberosKey',
          'Unprotect-AuthToken', 'Get-KerberosTicket', 'Get-NdrComplexType', 'Get-NtProcessUser'

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = 'Add-NtKeyHive', 'Get-NtDirectory', 'Get-NtEvent', 'Get-NtFile', 
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
               'Get-AccessibleService', 'Get-AccessibleHandle', 'Remove-NtKeyHive', 'New-NtToken',
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
               'Remove-NtTokenSecurityAttribute', 'Get-AccessibleEventTrace',
               'Test-NtTokenImpersonation', 'Get-AccessibleToken', 'Set-NtProcessJob', 
               'Get-AccessibleWnf', 'Get-AccessibleWindowStation', 'Get-NtProcessJob',
               'Get-NtWindowStation', 'Get-NtDesktop', 'New-NtWindowStation',
               'New-NtDesktop', 'Get-Win32Error', 'Set-NtKeyValue', 'Remove-NtKey',
               'Get-NtObjectInformation', 'Set-NtObjectInformation', 'Test-NtTokenPrivilege',
               'Format-NtJob', 'Add-NtSecurityDescriptorAce', 'New-NtSecurityAttribute',
               'Remove-NtSecurityDescriptorAce', 'Invoke-NtToken', 'Set-Win32SecurityDescriptor',
               'Reset-Win32SecurityDescriptor', 'Search-Win32SecurityDescriptor',
               'Get-Win32SecurityDescriptor', 'Compare-NtSid', 'Test-NtAceCondition',
               'Test-NtTokenGroup', 'Test-NtAccessMask', 'Grant-NtAccessMask',
               'Revoke-NtAccessMask', 'Select-NtSecurityDescriptorAce', 'Write-NtAudit',
               'New-AuthZResourceManager', 'New-AuthZContext', 'Get-AuthZGrantedAccess',
               'Add-AuthZSid', 'Remove-AuthZSid', 'Set-NtToken', 'Get-NtTokenDefaultDacl',
               'Set-NtTokenDefaultDacl'

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
        ReleaseNotes = '1.1.28
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

