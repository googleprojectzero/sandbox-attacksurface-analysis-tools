#  Copyright 2021 Google Inc. All Rights Reserved.
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

<#
.SYNOPSIS
Formats an object's security descriptor as text.
.DESCRIPTION
This cmdlet formats the security descriptor to text for display in the console or piped to a file
Uses Get-Win32SecurityDescriptor API to query the SD then uses the Format-NtSecurityDescriptor to
display.
.PARAMETER Type
Specify the SE object type for the path. Defaults to File.
.PARAMETER Name
Specify the name of the object for the security descriptor.
.PARAMETER SecurityInformation
Specify what parts of the security descriptor to format.
.PARAMETER Summary
Specify to only print a shortened format removing redundant information.
.PARAMETER ShowAll
Specify to format all security descriptor information including the SACL.
.PARAMETER HideHeader
Specify to not print the security descriptor header.
.PARAMETER AsSddl
Specify to format the security descriptor as SDDL.
.PARAMETER Container
Specify to display the access mask from Container Access Rights.
.PARAMETER MapGeneric
Specify to map access masks back to generic access rights for the object type.
.PARAMETER SDKName
Specify to format the security descriptor using SDK names where available.
.PARAMETER ResolveObjectType
Specify to try and resolve the object type GUID from the local Active Directory.
.PARAMETER Domain
Specify to indicate the domain to query the object type from when resolving. Defaults to the current domain.
.OUTPUTS
None
.EXAMPLE
Format-Win32SecurityDescriptor -Name "c:\windows".
Format the security descriptor for the c:\windows folder..
.EXAMPLE
Format-Win32SecurityDescriptor -Name "c:\windows" -AsSddl
Format the security descriptor of an object as SDDL.
.EXAMPLE
Format-Win32SecurityDescriptor -Name "c:\windows" -AsSddl -SecurityInformation Dacl, Label
Format the security descriptor of an object as SDDL with only DACL and Label.
.EXAMPLE
Format-Win32SecurityDescriptor -Name "Machine\Software" -Type RegistryKey
Format the security descriptor of a registry key.
#>
function Format-Win32SecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName = "FromName")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromName", Mandatory)]
        [string]$Name,
        [NtApiDotNet.Win32.Security.Authorization.SeObjectType]$Type = "File",
        [NtApiDotNet.SecurityInformation]$SecurityInformation = "AllBasic",
        [switch]$Container,
        [alias("ToSddl")]
        [switch]$AsSddl,
        [switch]$Summary,
        [switch]$ShowAll,
        [switch]$HideHeader,
        [switch]$MapGeneric,
        [switch]$SDKName,
        [switch]$ResolveObjectType,
        [string]$Domain
    )

    Get-Win32SecurityDescriptor -Name $Name -SecurityInformation $SecurityInformation `
        -Type $Type | Format-NtSecurityDescriptor -SecurityInformation $SecurityInformation `
        -Container:$Container -AsSddl:$AsSddl -Summary:$Summary -ShowAll:$ShowAll -HideHeader:$HideHeader `
        -DisplayPath $Name -MapGeneric:$MapGeneric -SDKName:$SDKName -ResolveObjectType:$ResolveObjectType `
        -Domain $Domain
}

<#
.SYNOPSIS
Get credential manager credentials.
.DESCRIPTION
This cmdlet gets available credentials from the credential mananger.
.PARAMETER Filter
Specify a filter for the credential target, for example DOMAIN*.
.PARAMETER All
Specify to return all credentials.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Credential.Credential[]
.EXAMPLE
Get-Win32Credential
Get Win32 credentials.
.EXAMPLE
Get-Win32Credential -All
Get all Win32 credentials.
.EXAMPLE
Get-Win32Credential -Filter "DOMAIN*"
Get Win32 credentials with a target name matching a pattern.
#>
function Get-Win32Credential {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [Parameter(ParameterSetName = "All")]
        [string]$Filter,
        [Parameter(ParameterSetName = "All")]
        [switch]$All,
        [Parameter(ParameterSetName = "FromName", Position = 0, Mandatory)]
        [string]$TargetName,
        [Parameter(ParameterSetName = "FromName", Position = 1, Mandatory)]
        [NtApiDotNet.Win32.Security.Credential.CredentialType]$Type
    )

    if ($PSCmdlet.ParameterSetName -eq "All") {
        $flags = if ($All) {
            "AllCredentials"
        } else {
            0
        }
        [NtApiDotNet.Win32.Security.Credential.CredentialManager]::GetCredentials($Filter, $flags) | Write-Output
    } else {
        [NtApiDotNet.Win32.Security.Credential.CredentialManager]::GetCredential($TargetName, $Type)
    }
}

<#
.SYNOPSIS
Backup credential manager credentials.
.DESCRIPTION
This cmdlet backs up a user's credential from the credential mananger. Needs SeTrustedCredmanAccessPrivilege to function.
.PARAMETER Token
Specify a token for the user to backup.
.PARAMETER Key
Specify optional key to encrypt the backup. Usually a password.
.PARAMETER KeyEncoded
Specify if the key is already encoded.
.INPUTS
None
.OUTPUTS
byte[]
.EXAMPLE
Backup-Win32Credential $token
Backup credentials for user in token.
.EXAMPLE
Backup-Win32Credential $token -Key 65, 0, 32, 0
Backup credentials for user in token encrypting with a key.
#>
function Backup-Win32Credential {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.NtToken]$Token,
        [byte[]]$Key,
        [switch]$KeyEncoded
    )

    Enable-NtTokenPrivilege SeTrustedCredmanAccessPrivilege
    [NtApiDotNet.Win32.Security.Credential.CredentialManager]::Backup($Token, $Key, $KeyEncoded)
}