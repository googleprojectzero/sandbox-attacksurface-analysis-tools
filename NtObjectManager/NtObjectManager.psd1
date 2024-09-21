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
ModuleVersion = '2.0.1'

# ID used to uniquely identify this module
GUID = 'ac251c97-67a6-4bc4-bb8a-5ae300e93030'

# Author of this module
Author = 'James Forshaw'

# Company or vendor of this module
CompanyName = 'Google LLC.'

# Copyright statement for this module
Copyright = '(c) 2016-2023 Google LLC. All rights reserved.'

# Description of the functionality provided by this module
Description = 'This module adds a provider and cmdlets to access the NT object manager namespace.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '3.0'

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
DotNetFrameworkVersion = '4.6.1'

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
CLRVersion = '4.0'

# Format files (.ps1xml) to be loaded when importing this module
FormatsToProcess = 'Formatters.ps1xml'

# Type files (.ps1xml) to be loaded when importing this module
TypesToProcess = 'TypeExtensions.ps1xml'

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = 'Get-AccessibleAlpcPort', 'Set-NtTokenPrivilege',
          'Set-NtTokenIntegrityLevel', 'Get-NtProcessMitigations', 'New-NtKernelCrashDump', 'New-NtObjectAttributes',
          'New-NtSecurityQualityOfService', 'Get-NtLicenseValue', 'Get-NtSystemEnvironmentValue', 'New-Win32Process',
          'New-NtEaBuffer', 'New-NtSectionImage', 'New-Win32ProcessConfig', 'Get-NtTokenFromProcess', 'Get-Win32ModuleManifest',
          'New-NtProcess', 'New-NtProcessConfig', 'Get-NtFilePath', 'Show-NtTokenEffective', 'Show-NtSecurityDescriptor', 'Get-NtIoControlCode',
          'Import-NtObject', 'Export-NtObject', 'Get-ExecutionAlias', 'Set-ExecutionAlias', 'Set-ExecutionAlias', 'Show-NtToken', 'Show-NtSection',
          'Resolve-NtObjectAddress', 'Get-NtSecurityDescriptor', 'Get-NtSecurityDescriptorIntegrityLevel',
          'Set-NtSecurityDescriptor', 'Add-NtVirtualMemory', 'Get-NtVirtualMemory', 'Remove-NtVirtualMemory', 'Set-NtVirtualMemory',
          'Read-NtVirtualMemory', 'Write-NtVirtualMemory', 'Get-EmbeddedAuthenticodeSignature', 'Get-NtSidName', 'New-SymbolResolver', 
          'New-NdrParser', 'Format-NdrComplexType', 'Format-NdrProcedure', 'Format-NdrComProxy', 'Get-NdrComProxy', 'Get-NdrRpcServerInterface',
          'Format-NdrRpcServerInterface', 'Get-NtWnf', 'Get-NtCachedSigningLevel', 
          'Get-NtFilePathType', 'New-NtType', 'Get-NtAlpcServer', 'Get-RpcEndpoint', 'Get-RpcServer', 'Set-GlobalSymbolResolver',
          'Copy-NtToken', 'Get-RpcAlpcServer', 'Get-NtObjectFromHandle', 'Start-Win32ChildProcess', 'Get-NtKeyValue',
          'Start-NtFileOplock', 'Format-RpcServer', 'Get-NtProcessMitigationPolicy',
          'Set-NtProcessMitigationPolicy', 'Format-NtSecurityDescriptor', 'Get-AppContainerProfile', 'New-AppContainerProfile',
          'Get-RpcClient', 'Format-RpcClient', 'Set-RpcServer', 'Connect-RpcClient', 'New-RpcContextHandle', 'Format-RpcComplexType',
          'Get-Win32File', 'Close-NtObject', 'Start-AccessibleScheduledTask', 'Get-NtFileEa', 'Set-NtFileEa',
          'Suspend-NtProcess', 'Resume-NtProcess', 'Stop-NtProcess', 'Suspend-NtThread', 'Resume-NtThread', 'Stop-NtThread',
          'Format-NtToken', 'Remove-NtTokenPrivilege', 'Get-NtTokenPrivilege', 'Get-NtLocallyUniqueId', 'Get-NtTokenGroup',
          'Get-NtTokenSid', 'Set-NtTokenSid', 'Set-NtTokenGroup', 'Get-NtDesktopName', 'Get-NtWindowStationName',
          'Get-NtWindow', 'Format-HexDump', 'Get-NtTypeAccess', 'Get-NtAtom', 'Add-NtAtom', 'Remove-NtAtom',
          'Import-Win32Module', 'Get-Win32Module', 'Get-Win32ModuleExport', 'Get-Win32ModuleImport', 'Get-NtDirectoryEntry',
          'Remove-NtKeyValue', 'Read-LsaCredential', 'Get-LsaPackage', 'New-LsaCredentialHandle', 'New-LsaServerContext',
          'New-LsaClientContext', 'Update-LsaServerContext', 'Update-LsaClientContext', 'Get-LsaAccessToken', 'Get-NtKernelModule',
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
          'Set-NtAuditSecurity', 'Format-LsaAuthToken', 'Get-LsaAuthToken', 'Test-LsaContext', 'Get-NtLogonSession',
          'Get-NtAccountRight', 'Get-NtAccountRightSid', 'Get-NtConsoleSession', 'Get-ServicePrincipalName',
          'Get-NtTokenId', 'Get-LsaCredential', 'Export-LsaAuthToken', 'Import-LsaAuthToken', 'Get-MD4Hash',
          'Format-ASN1DER', 'Import-KerberosKeyTab', 'Export-KerberosKeyTab', 'New-KerberosKey', 'Get-KerberosKey',
          'Unprotect-LsaAuthToken', 'Get-KerberosTicket', 'Get-NdrComplexType', 'Get-NtProcessUser',
          'Get-NtProcessEnvironment', 'Split-Win32CommandLine', 'Send-NtWindowMessage', 'Get-NtKeyHive',
          'Backup-NtKey', 'Restore-NtKey', 'Enable-NtTokenVirtualization', 'Disable-NtTokenVirtualization',
          'Read-NtFile', 'Write-NtFile', 'Get-FilterConnectionPort', 'Get-FilterDriver', 
          'Get-FilterDriverInstance', 'Get-FilterDriverVolume', 'Get-FilterDriverVolumeInstance',
          'Add-NtEaBuffer', 'Remove-NtFileEa', 'Get-NtDeviceSetupClass', 'Get-NtDeviceNode',
          'Get-NtDeviceInterfaceClass', 'Get-NtDeviceProperty', 'Get-NtDeviceNodeChild',
          'Get-NtDeviceInterfaceInstance', 'Get-NtDeviceNodeParent', 'Get-NtDeviceNodeStack',
          'Get-NtFileItem', 'Get-NtFileChange', 'Lock-NtFile', 'Unlock-NtFile',
          'Get-NtFileDisposition', 'Set-NtFileDisposition', 'Wait-AsyncTaskResult', 'Get-NtFile8dot3Name',
          'Send-FilterConnectionPort', 'Test-NtFileDriverPath', 'Get-NtMountPoint', 'New-NtFileReparseBuffer',
          'Get-NtFileQuota', 'Set-NtFileQuota', 'Read-NtFileUsnJournal', 'Confirm-NtFileOplock',
          'Start-AppModelApplication', 'Get-NtThreadContext', 'Set-NtThreadContext', 'Remove-AppContainerProfile',
          'Get-AppModelApplicationPolicy', 'Test-NtProcessJob', 'Get-AppxDesktopBridge', 'Stop-NtJob',
          'Get-NtThreadWorkOnBehalfTicket', 'Set-NtThreadWorkOnBehalfTicket', 'Get-NtThreadContainerId',
          'Set-NtThreadContainer', 'Clear-NtThreadWorkOnBehalfTicket', 'Compare-NtSigningLevel',
          'Get-NtSystemInformation', 'Get-NtSigningLevel', 'Get-X509Certificate', 'Set-NtCachedSigningLevel',
          'Invoke-NtEnclave', 'Add-NtAccountRight', 'Remove-NtAccountRight', 'Start-Win32DebugConsole',
          'Get-Win32Service', 'Test-NtProcess', 'Get-NtApiSet', 'Clear-NtSidName', 'Add-NtSidName',
          'Remove-NtSidName', 'New-Win32Service', 'Remove-Win32Service', 'Test-NtTokenCapability',
          'New-Win32DebugConsole', 'Read-Win32DebugConsole', 'Get-Win32ServiceSecurityDescriptor',
          'Disconnect-RpcClient', 'Enable-NtTokenPrivilege', 'Disable-NtTokenPrivilege', 'Get-Win32ModuleSymbolFile',
          'Get-RpcStringBinding', 'Start-Win32Service', 'Get-Win32ServiceConfig', 'Get-LsaContextSignature',
          'Test-LsaContextSignature', 'Protect-LsaContextMessage', 'Unprotect-LsaContextMessage',
          'New-LsaSecurityBuffer', 'Get-LsaSchannelCredential', 'Get-LsaCredSSPCredential',
          'ConvertFrom-LsaSecurityBuffer', 'ConvertFrom-NtSid', 'Get-AppModelLoopbackException', 
          'Add-AppModelLoopbackException', 'Remove-AppModelLoopbackException', 'Get-NtSDKName',
          'Wait-Win32Service', 'Send-Win32Service', 'Get-Win32ServiceTrigger', 'Set-Win32ServiceSecurityDescriptor',
          'Restart-Win32Service', 'Test-Win32Service', 'Format-KerberosTicket', 'ConvertFrom-HexDump', 
          'Get-Win32ModuleResource', 'Get-LsaPolicy', 'Connect-SamServer', 'Get-SamDomain', 'Get-SamUser',
          'Get-SamAlias', 'Get-SamGroup', 'Get-LsaPrivateData', 'Set-LsaPrivateData', 'Get-LsaAccount',
          'Get-LsaTrustedDomain', 'Get-LsaSecret', 'Get-SamAliasMember', 'Get-SamGroupMember',
          'Get-DsExtendedRight', 'Get-DsSchemaClass', 'Get-LsaName', 'Get-LsaSid', 'Protect-RC4',
          'Get-DsObjectSid', 'Get-DsObjectSchemaClass', 'ConvertTo-ObjectTypeTree', 'Get-DsSchemaAttribute',
          'Get-DsHeuristics', 'New-SamUser', 'Get-DsSDRightsEffective', 'Search-DsObjectSid',
          'Get-Win32Credential', 'Backup-Win32Credential', 'Select-BinaryString', 'Get-FwEngine',
          'Get-FwLayer', 'Get-FwFilter', 'Get-FwSubLayer', 'Remove-FwFilter', 'Format-FwFilter',
          'New-FwConditionBuilder', 'Add-FwFilter', 'Get-FwGuid', 'New-FwFilterTemplate',
          'Get-FwAleEndpoint', 'Get-FwToken', 'Get-SocketSecurity', 'Set-SocketSecurity',
          'Set-SocketPeerTargetName', 'Get-IkeSecurityAssociation', 'Get-FwSession',
          'Reset-NtTokenGroup', 'Enable-NtTokenGroup', 'Disable-NtTokenGroup', 'Get-FwNetEvent',
          'Read-FwNetEvent', 'New-FwNetEventListener', 'Start-FwNetEventListener', 'Get-IPsecSaContext',
          'Get-FwEngineOption', 'Set-FwEngineOption', 'New-FwNetEventTemplate', 'Add-FwCondition',
          'Get-FwCallout', 'Add-RpcClientSecurityContext', 'Set-RpcClientSecurityContext', 
          'Get-RpcClientSecurityContext', 'Get-RpcServicePrincipalName', 'Get-FwProvider',
          'Update-Win32Environment', 'New-KerberosChecksum', 'New-KerberosPrincipalName',
          'New-KerberosAuthenticator', 'New-KerberosApRequest', 'New-KerberosTicket',
          'Add-KerberosTicket', 'Remove-KerberosTicket', 'New-KerberosTicketCache',
          'New-KerberosKey', 'Remove-Win32Credential', 'Set-Win32Credential', 'Protect-Win32Credential',
          'Unprotect-Win32Credential', 'Rename-KerberosTicket', 'New-KerberosError', 'Add-KerberosKdcPin',
          'Clear-KerberosKdcPin', 'Test-NtSid', 'New-KerberosTgsRequest', 'Send-KerberosKdcRequest',
          'New-KerberosAsRequest', 'New-KerberosKdcServer', 'New-KerberosKdcServerUser',
          'New-KerberosAuthorizationData', 'Resolve-KerberosKdcAddress', 'Get-ASN1DER',
          'New-ASN1DER', 'New-KerberosKeyTab', 'Export-KerberosTicketCache', 'Import-KerberosTicketCache',
          'Export-KerberosTicket', 'Import-KerberosTicket', 'New-Win32MemoryBuffer', 'Get-HyperVSocketTable',
          'New-RpcTransportSecurity', 'Get-RpcInterface', 'New-RpcClientTransportConfig', 'Get-HyperVSocketAddress',
          'Get-RpcClientAssociationGroupId', 'Get-ComProxyFile', 'Format-ComProxyFile', 'Get-NtImageFile',
          'Select-NtImageFile'

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
               'New-NtFileHardlink', 'Test-NetworkAccess', 'Get-AccessibleScheduledTask',
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
               'Set-NtTokenDefaultDacl', 'Get-NtKeySymbolicLinkTarget', 'New-NtKeySymbolicLink',
               'Rename-NtFile', 'Get-NtFileVolumeInformation', 'Set-NtFileVolumeInformation',
               'Send-NtFileControl', 'Get-NtFileAttribute', 'Set-NtFileAttribute', 'Get-NtFileShareProcess',
               'Get-NtFileCompression', 'Set-NtFileCompression',  'Get-NtFileLink', 'Get-NtFileStream',
               'Get-NtFileObjectId', 'Get-NtFileId', 'Set-NtFileObjectId', 'Remove-NtFileObjectId',
               'Get-NtFileFinalPath', 'Add-NtThreadApc', 'New-NtThread', 'New-NtEnclave', 'Get-RandomByte',
               'Get-RunningScheduledTask', 'Set-Win32ServiceConfig', 'ConvertTo-NtSecurityDescriptor',
               'Compare-NtSecurityDescriptor', 'Clear-AuthZSid', 'Get-AccessibleDsObject',
               'Get-Win32GrantedAccess', 'Get-AccessibleFwObject', 'New-KerberosKdcProxy', 'Get-RpcProcess'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = 'Get-NtEaBuffer', 'Set-NtEaBuffer', 'Get-AuthPackage', 'Read-AuthCredential', 'Get-AuthCredential', 
                'Get-AuthCredentialHandle', 'Get-AuthClientContext', 'Get-AuthServerContext', 'Update-AuthClientContext', 
                'Update-AuthServerContext', 'Get-AuthAccessToken', 'Get-AuthToken', 'Test-AuthContext', 'Format-AuthToken', 
                'Export-AuthToken', 'Import-AuthToken', 'Unprotect-AuthToken', 'Out-HexDump', 'Get-NtMappedSection',
                'Unprotect-RC4'

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
        ReleaseNotes = '2.0.1.
--------
* Improvements to RPC tooling.

NOTE: This version is a major refactor of the code. Scripts which only use exposed PowerShell commands
should work when upgrading from v1 to v2, however if you use internal APIs it will almost certainly
not work due to refactoring and renaming. Going forward it''s recommended to not rely on internal 
APIs to work across releases.
'

    } # End of PSData hashtable
    
 } # End of PrivateData hashtable

}

