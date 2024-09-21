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
Exports keys to a Kerberos KeyTab file file.
.DESCRIPTION
This cmdlet exports keys to a Kerberos KeyTab file file.
.PARAMETER Key
List of keys to write to the file.
.PARAMETER Path
The path to the file to export.
.INPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey
.OUTPUTS
None
#>
function Export-KerberosKeyTab {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Path,
        [Parameter(Position = 1, Mandatory, ValueFromPipeline)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey[]]$Key
    )

    BEGIN {
        $keys = @()
    }

    PROCESS {
        foreach($k in $Key) {
            $keys += $k
        }
    }

    END {
        $key_arr = [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey[]]$keys
        $keytab = [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosUtils]::GenerateKeyTabFile($key_arr)
        Write-BinaryFile -Path $Path -Byte $keytab
    }
}

<#
.SYNOPSIS
Imports a Kerberos KeyTab file into a list of keys.
.DESCRIPTION
This cmdlet imports a Kerberos KeyTab file into a list of keys.
.PARAMETER Path
The path to the file to import.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey[]
#>
function Import-KerberosKeyTab {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Path
    )

    $Path = Resolve-Path -Path $Path -ErrorAction Stop
    [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosUtils]::ReadKeyTabFile($Path) | Write-Output
}

<#
.SYNOPSIS
Create a new Kerberos keytab file from a user's credentials.
.DESCRIPTION
This cmdlet creates a new Kerberos keytab file from a user's credentials.
.PARAMETER Credential
Credentials for the authentication.
.PARAMETER ReadCredential
Specify to read the credentials from the console if not specified explicitly.
.PARAMETER UserName
The username to use.
.PARAMETER Domain
The domain to use.
.PARAMETER Password
The password to use.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey[]
#>
function New-KerberosKeyTab {
    [CmdletBinding(DefaultParameterSetName="FromCreds")]
    Param(
        [Parameter(Mandatory, ParameterSetName="FromCreds")]
        [NtCoreLib.Win32.Security.Authentication.AuthenticationCredentials]$Credential,
        [Parameter(ParameterSetName="FromParts")]
        [switch]$ReadCredential,
        [Parameter(ParameterSetName="FromParts")]
        [string]$UserName,
        [Parameter(ParameterSetName="FromParts")]
        [string]$Domain,
        [Parameter(ParameterSetName="FromParts")]
        [alias("SecurePassword")]
        [NtObjectManager.Utils.PasswordHolder]$Password
    )

    if ($PSCmdlet.ParameterSetName -eq "FromParts") {
        if ($ReadCredential) {
            $Credential = Read-LsaCredential -UserName $UserName -Domain $Domain `
                    -Password $Password
        } else {
            $Credential = Get-LsaCredential -UserName $UserName -Domain $Domain `
                    -Password $Password
        }
    }

    [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosKeySet]::GetKeyTab($Credential) | Write-Output
}

<#
.SYNOPSIS
Gets a Kerberos Key from a raw key or password.
.DESCRIPTION
This cmdlet gets a Kerberos Key from a raw key or password.
.PARAMETER Password
The password to convert to a key.
.PARAMETER KeyType
The key encryption type.
.PARAMETER Iterations
The number of iterations for the key derivation.
.PARAMETER Principal
The principal associated with the key.
.PARAMETER Salt
The salt for the key, if not specified will try and derive from the principal.
.PARAMETER Base64Key
The key as a base64 string.
.PARAMETER HexKey
The key as a hex string.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey
#>
function Get-KerberosKey {
    [CmdletBinding(DefaultParameterSetName="FromPassword")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromPassword")]
        [NtObjectManager.Utils.PasswordHolder]$Password,
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromKey")]
        [byte[]]$Key,
        [Parameter(Mandatory, ParameterSetName="FromBase64Key")]
        [string]$Base64Key,
        [Parameter(Mandatory, ParameterSetName="FromHexKey")]
        [string]$HexKey,
        [Parameter(Position = 1, Mandatory, ParameterSetName="FromPassword")]
        [Parameter(Position = 1, Mandatory, ParameterSetName="FromKey")]
        [Parameter(Mandatory, ParameterSetName="FromBase64Key")]
        [Parameter(Mandatory, ParameterSetName="FromHexKey")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosEncryptionType]$KeyType,
        [Parameter(ParameterSetName="FromPassword")]
        [int]$Interations = 4096,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosNameType]$NameType = "PRINCIPAL",
        [Parameter(Position = 2, Mandatory, ParameterSetName="FromPassword")]
        [Parameter(Position = 2, ParameterSetName="FromKey")]
        [Parameter(ParameterSetName="FromBase64Key")]
        [Parameter(ParameterSetName="FromHexKey")]
        [string]$Principal,
        [Parameter(ParameterSetName="FromPassword")]
        [string]$Salt,
        [uint32]$Version = 1,
        [Parameter(ParameterSetName="FromKey")]
        [Parameter(ParameterSetName="FromBase64Key")]
        [Parameter(ParameterSetName="FromHexKey")]
        [DateTime]$Timestamp = [DateTime]::Now
    )

    try {
        $k = switch($PSCmdlet.ParameterSetName) {
            "FromPassword" {
                [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]::DeriveKey($KeyType, $Password.ToPlainText(), $Interations, $NameType, $Principal, $Salt, $Version)
            }
            "FromKey" {
                [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]::new($KeyType, $Key, $NameType, $Principal, $Timestamp, $Version)
            }
            "FromBase64Key" {
                $Key = [System.Convert]::FromBase64String($Base64Key)
                [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]::new($KeyType, $Key, $NameType, $Principal, $Timestamp, $Version)
            }
            "FromHexKey" {
                $Key = ConvertFrom-HexDump -Hex $HexKey
                [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]::new($KeyType, $Key, $NameType, $Principal, $Timestamp, $Version)
            }
        }
        $k | Write-Output
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Create a new random kerberos key.
.DESCRIPTION
This cmdlet creates a new Kerberos Key.
.PARAMETER KeyType
The key encryption type.
.PARAMETER Key
The existing key to use the encryption type from.
.PARAMETER Name
The principal name to use.
.PARAMETER Realm
The realm to use.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey
#>
function New-KerberosKey {
    [CmdletBinding(DefaultParameterSetName="FromEncType")]
    Param(
        [Parameter(Mandatory, ParameterSetName="FromEncType", Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosEncryptionType]$KeyType,
        [Parameter(Mandatory, ParameterSetName="FromKey", Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$Key,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]$Name,
        [string]$Realm
    )

    if ($PSCmdlet.ParameterSetName -eq "FromKey") {
        $Key.GenerateKey($Name, $Realm)
    } else {
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]::GenerateKey($KeyType, $Name, $Realm)
    }
}

<#
.SYNOPSIS
Get Kerberos Ticket.
.DESCRIPTION
This cmdlet gets a kerberos Ticket, or multiple tickets.
.PARAMETER LogonId
Specify a logon ID to query for tickets.
.PARAMETER LogonSession
Specify a logon session to query for tickets.
.PARAMETER TargetName
Specify a target name to query for a ticket. If it doesn't exist get a new one.
.PARAMETER CacheOnly
Specify to only lookup the TargetName in the cache.
.PARAMETER CredHandle
Specify a credential handle to query the ticket from.
.PARAMETER Cache
Specify to get a ticket from a local cache.
.PARAMETER InfoOnly
Specify to only return information from the cache not the tickets themselves.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosExternalTicket
#>
function Get-KerberosTicket {
    [CmdletBinding(DefaultParameterSetName="CurrentLuid")]
    Param(
        [Parameter(Position = 0, ParameterSetName="FromTarget", Mandatory)]
        [Parameter(Position = 0, ParameterSetName="FromLocalCache", Mandatory)]
        [string]$TargetName,
        [Parameter(Position = 0, ParameterSetName="FromLuid", Mandatory)]
        [Parameter(Position = 1, ParameterSetName="FromTarget")]
        [NtCoreLib.Luid]$LogonId = [NtCoreLib.Luid]::new(0),
        [Parameter(Position = 0, ParameterSetName="FromLogonSession", ValueFromPipeline, Mandatory)]
        [NtCoreLib.Win32.Security.Authentication.LogonSession[]]$LogonSession,
        [Parameter(ParameterSetName="FromTarget")]
        [NtCoreLib.Win32.Security.Authentication.CredentialHandle]$CredHandle,
        [Parameter(ParameterSetName="FromLocalCache", Mandatory)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]$Cache,
        [Parameter(ParameterSetName="FromTarget")]
        [Parameter(ParameterSetName="FromLocalCache")]
        [switch]$CacheOnly,
        [Parameter(ParameterSetName="FromLuid")]
        [Parameter(ParameterSetName="CurrentLuid")]
        [Parameter(ParameterSetName="FromLogonSession")]
        [switch]$InfoOnly,
        [Parameter(ParameterSetName="FromTarget")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosRetrieveTicketFlags]$Flags = 0,
        [Parameter(ParameterSetName="FromTarget")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketFlags]$TicketFlags = 0,
        [Parameter(ParameterSetName="FromTarget")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosEncryptionType]$EncryptionType = 0
    )

    PROCESS {
        try {
            switch($PSCmdlet.ParameterSetName) {
                "CurrentLuid" {
                    if ($InfoOnly) {
                        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCacheInfo() | Write-Output
                    } else {
                        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCache() | Write-Output
                    }
                }
                "FromLuid" {
                    if ($InfoOnly) {
                        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCacheInfo($LogonId) | Write-Output
                    } else {
                        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCache($LogonId) | Write-Output
                    }
                }
                "FromLogonSession" {
                    foreach($l in $LogonSession) {
                        if ($InfoOnly) {
                            [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCacheInfo($l.LogonId) | Write-Output
                        } else {
                            [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCache($l.LogonId) | Write-Output
                        }
                    }
                }
                "FromTarget" {
                    $Flags = $Flags -bor "AsKerbCred"
                    if ($CacheOnly) {
                        $Flags = $Flags -bor "UseCacheOnly"
                    }

                    [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::RetrieveTicket($TargetName, $LogonId, $CredHandle, $Flags, $TicketFlags, $EncryptionType) | Write-Output
                }
                "FromLocalCache" {
                    $Cache.GetTicket($TargetName, $CacheOnly)
                }
            }
        } catch {
            Write-Error $_
        }
    }
}

<#
.SYNOPSIS
Format a Kerberos Ticket.
.DESCRIPTION
This cmdlet formats a kerberos Ticket, or multiple tickets.
.PARAMETER Ticket
Specify the ticket to format.
.INPUTS
None
.OUTPUTS
string
#>
function Format-KerberosTicket {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicket]$Ticket
    )

    PROCESS {
        $Ticket.Format()
    }
}

<#
.SYNOPSIS
Create a new Kerberos checksum.
.DESCRIPTION
This cmdlet creates a new Kerberos checksum. It defaults to creating a GSSAPI checksum
which is the most common type.
.PARAMETER Credential
Specify a Kerberos credentials to use for delegation.
.PARAMETER ContextFlags
Specify context flags for the checksum.
.PARAMETER ChannelBinding
Specify the channel binding.
.PARAMETER Extenstion
Specify additional extension data.
.PARAMETER DelegationOptionIdentifier
Specify the delegation options identifier.
.PARAMETER Type
Specify the type of checksum.
.PARAMETER Checksum
Specify the checksum value.
.PARAMETER Key
Specify a kerberos key to generate the checksum.
.PARAMETER KeyUsage
Specify the key usage for the checksum calculation.
.PARAMETER Data
Specify the data to checksum.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosChecksum
#>
function New-KerberosChecksum {
    [CmdletBinding(DefaultParameterSetName="FromGssApi")]
    Param(
        [Parameter(ParameterSetName="FromGssApi")]
        [byte[]]$ChannelBinding,
        [Parameter(ParameterSetName="FromGssApi")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosChecksumGSSApiFlags]$ContextFlags = 0,
        [Parameter(ParameterSetName="FromGssApi")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosCredential]$Credential,
        [Parameter(ParameterSetName="FromGssApi")]
        [int]$DelegationOptionIdentifier = 0,
        [Parameter(ParameterSetName="FromGssApi")]
        [byte[]]$Extension,
        [Parameter(Mandatory, ParameterSetName="FromRaw")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosChecksumType]$Type,
        [Parameter(Mandatory, ParameterSetName="FromRaw")]
        [byte[]]$Checksum,
        [Parameter(Mandatory, ParameterSetName="FromKey")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$Key,
        [Parameter(Mandatory, ParameterSetName="FromKey")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosKeyUsage]$KeyUsage,
        [Parameter(Mandatory, ParameterSetName="FromKey")]
        [byte[]]$Data
    )

    PROCESS {
        switch($PSCmdlet.ParameterSetName) {
            "FromGssApi" {
                [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosChecksumGSSApi]::new($ContextFlags, $ChannelBinding, $DelegationOptionIdentifier, $Credential, $Extension)
            }
            "FromRaw" {
                [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosChecksum]::new($Type, $Checksum)
            }
            "FromKey" {
                [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosChecksum]::Create($Key, $Data, $KeyUsage)
            }
        }
    }
}

<#
.SYNOPSIS
Create a new Kerberos principal name.
.DESCRIPTION
This cmdlet creates a new Kerberos principal name.
.PARAMETER Type
Specify the type of principal name.
.PARAMETER NamePart
Specify the list of name parts.
.PARAMETER Name
Specify the name parts as a single name with forward slashes.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName
#>
function New-KerberosPrincipalName {
    [CmdletBinding(DefaultParameterSetName="FromName")]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosNameType]$Type,
        [Parameter(Mandatory, Position = 1, ParameterSetName = "FromName")]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName = "FromNamePart")]
        [string[]]$NamePart
    )


    switch($PSCmdlet.ParameterSetName) {
        "FromName" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]::new($Type, $Name)
        }
        "FromNamePart" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]::new($Type, $NamePart)
        }
    }
}

<#
.SYNOPSIS
Create a new Kerberos authenticator.
.DESCRIPTION
This cmdlet creates a new Kerberos authenticator. Note this doesn't encrypt it, it'll be in plain text.
.PARAMETER Checksum
Specify a Kerberos checksum.
.PARAMETER ClientRealm
Specify the realm for the client.
.PARAMETER ClientName
Specify the name for the client.
.PARAMETER SubKey
Specify a subkey.
.PARAMETER SequenceNumber
Specify a sequence number.
.PARAMETER AuthorizationData
Specify authorization data.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticator
#>
function New-KerberosAuthenticator {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$ClientRealm,
        [Parameter(Mandatory, Position = 1)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]$ClientName,
        [datetime]$ClientTime = [datetime]::MinValue,
        [int]$ClientUSec = 0,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosChecksum]$Checksum,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$SubKey,
        [System.Nullable[int]]$SequenceNumber = $null,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthorizationData[]]$AuthorizationData
    )

    if ($ClientTime -eq [datetime]::MinValue) {
        $ClientTime = [datetime]::Now
    }
    [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticator]::Create($ClientRealm, $ClientName, $ClientTime, `
            $ClientUSec, $Checksum, $SubKey, $SequenceNumber, $AuthorizationData)
}

<#
.SYNOPSIS
Create a new Kerberos AP-REQ token.
.DESCRIPTION
This cmdlet creates a new Kerberos AP-REQ token.
.PARAMETER Ticket
Specify a Kerberos ticket.
.PARAMETER Authenticator
Specify the authenticator.
.PARAMETER AuthenticatorKey
Specify the key to encrypt the authenticator.
.PARAMETER AuthenticatorKeyVersion
Specify the key version to encrypt the authenticator.
.PARAMETER TicketKey
Specify the key to encrypt the ticket.
.PARAMETER AuthenticatorKeyVersion
Specify the key version to encrypt the ticket.
.PARAMETER RawToken
Specify to return a raw token with no GSSAPI header.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAPRequestAuthenticationToken
#>
function New-KerberosApRequest {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicket]$Ticket,
        [Parameter(Mandatory, Position = 1)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosEncryptedData]$Authenticator,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAPRequestOptions]$Options = 0,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$AuthenticatorKey,
        [System.Nullable[int]]$AuthenticatorKeyVersion,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$TicketKey,
        [System.Nullable[int]]$TicketKeyVersion,
        [switch]$RawToken
    )

    [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAPRequestAuthenticationToken]::Create($Ticket, $Authenticator, $Options, `
                $AuthenticatorKey, $AuthenticatorKeyVersion, $TicketKey, $TicketKeyVersion, $RawToken)
}

<#
.SYNOPSIS
Create a new Kerberos  ticket.
.DESCRIPTION
This cmdlet creates a new Kerberos ticket.
.PARAMETER Realm
Specify the ticket realm.
.PARAMETER ServerName
Specify the server name.
.PARAMETER EncryptedData
Specify the ticket encrypted data.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicket
#>
function New-KerberosTicket {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Realm,
        [Parameter(Mandatory, Position = 1)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]$ServerName,
        [Parameter(Mandatory, Position = 2)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosEncryptedData]$EncryptedData
    )

    [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicket]::Create($Realm, $ServerName, $EncryptedData)
}

<#
.SYNOPSIS
Add a kerberos ticket to the cache.
.DESCRIPTION
This cmdlet adds an existing kerberos ticket to the system cache.
.PARAMETER Credential
Specify the ticket credential.
.PARAMETER Key
Specify the ticket credential key if needed.
.PARAMETER LogonId
Specify the logon ID for the ticket cache.
.PARAMETER Cache
Specify a local cache to add the ticket to.
.INPUTS
None
.OUTPUTS
None
#>
function Add-KerberosTicket {
    [CmdletBinding(DefaultParameterSetName="FromSystem")]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosCredential]$Credential,
        [Parameter(ParameterSetName="FromSystem")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$Key,
        [Parameter(ParameterSetName="FromSystem")]
        [NtCoreLib.Luid]$LogonId = 0,
        [Parameter(ParameterSetName="FromLocalCache", Mandatory)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]$Cache
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromSystem" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::SubmitTicket($Credential, $LogonId, $Key)
        }
        "FromLocalCache" {
            $Cache.AddTicket($Credential)
        }
    }
}

<#
.SYNOPSIS
Remove a kerberos ticket from the cache.
.DESCRIPTION
This cmdlet removes a kerberos ticket from the user's ticket cache.
.PARAMETER Realm
Specify the ticket realm.
.PARAMETER ServerName
Specify the server name.
.PARAMETER LogonId
Specify the logon ID for the ticket cache.
.INPUTS
None
.OUTPUTS
None
#>
function Remove-KerberosTicket {
    [CmdletBinding(DefaultParameterSetName="FromName")]
    Param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromName")]
        [string]$Realm,
        [Parameter(Mandatory, Position = 1, ParameterSetName="FromName")]
        [string]$ServerName,
        [Parameter(Position = 2, ParameterSetName="FromName")]
        [NtCoreLib.Luid]$LogonId = 0,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromAll")]
        [switch]$All
    )

    [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::PurgeTicketCache($LogonId, $ServerName, $Realm)
}

<#
.SYNOPSIS
Create a new local Kerberos cache.
.DESCRIPTION
This cmdlet creates a new local Kerberos ticket cache. Defaults to populating from the current system cache.
.PARAMETER CreateClient
Create a client when initializing from the system cache or a list of tickets.
.PARAMETER LogonId
Specify the logon ID for the system cache to use.
.PARAMETER Hostname
Specify the hostname of the KDC to use for the cache.
.PARAMETER Port
Specify the port number of the KDC to use for the cache.
.PARAMETER Credential
Specify the TGT credentials to use for the cache.
.PARAMETER Realm
Specify the realm to use for the cache.
.PARAMETER AdditionalTicket
Specify additional tickets to add to the new cache.
.PARAMETER Key
Specify the user key to authenticate the new ticket cache.
.PARAMETER Request
Specify an AS-REQ to authentication the user for the new ticket cache.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache
#>
function New-KerberosTicketCache {
    [CmdletBinding(DefaultParameterSetName="FromSystem")]
    Param(
        [Parameter(ParameterSetName="FromSystem")]
        [Parameter(ParameterSetName="FromTickets")]
        [switch]$CreateClient,
        [Parameter(ParameterSetName="FromSystem")]
        [NtCoreLib.Luid]$LogonId = 0,
        [Parameter(ParameterSetName="FromTgt", Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosCredential]$Credential,
        [Parameter(ParameterSetName="FromKey", Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$Key,
        [Parameter(ParameterSetName="FromRequest", Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosASRequestBase]$Request,
        [Parameter(ParameterSetName="FromTgt")]
        [Parameter(ParameterSetName="FromKey")]
        [string]$Hostname,
        [Parameter(ParameterSetName="FromTgt")]
        [Parameter(ParameterSetName="FromKey")]
        [int]$Port = 88,
        [Parameter(ParameterSetName="FromTgt")]
        [string]$Realm = [NullString]::Value,
        [Parameter(ParameterSetName="FromTgt")]
        [Parameter(Mandatory, ParameterSetName="FromTickets")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosExternalTicket[]]$AdditionalTicket
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromSystem" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]::FromSystemCache($CreateClient, $LogonId)
        }
        "FromTgt" {
            $client = [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosKDCClient]::CreateTCPClient($Hostname, $Port)
            [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]::new($Credential, $client, $Realm, $AdditionalTicket)
        }
        "FromKey" {
            $client = [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosKDCClient]::CreateTCPClient($Hostname, $Port)
            [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]::FromClient($client, $Key)
        }
        "FromRequest" {
            $client = [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosKDCClient]::CreateTCPClient($Hostname, $Port)
            [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]::FromClient($client, $Request)
        }
        "FromTickets" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]::FromTickets($AdditionalTicket, $CreateClient)
        }
    }
}

<#
.SYNOPSIS
Import a Kerberos ticket cache from a file.
.DESCRIPTION
This cmdlet imports a Kerberos ticket cache from an MIT style ccache file.
.PARAMETER Path
Specify the path to import.
.PARAMETER CreateClient
Specify to create a KDC client.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache
#>
function Import-KerberosTicketCache {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Path,
        [switch]$CreateClient
    )

    $Path = Resolve-Path $Path
    if ($null -ne $Path) {
        [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]::FromFile($Path, $CreateClient)
    }
}

<#
.SYNOPSIS
Export a Kerberos ticket cache to a file.
.DESCRIPTION
This cmdlet exports a Kerberos ticket cache to an MIT style ccache file.
.PARAMETER Cache
Specify the cache to export.
.PARAMETER Path
Specify the path to export to.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache
#>
function Export-KerberosTicketCache {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]$Cache,
        [Parameter(Mandatory, Position = 1)]
        [string]$Path
    )

    $cache_bytes = $cache.ToCredentialFile().Export($Path)
    Write-BinaryFile -Path $Path -Byte $cache_bytes
}

<#
.SYNOPSIS
Rename the kerberos ticket's server name.
.DESCRIPTION
This cmdlet renames the server name of a Kerberos ticket.
.PARAMETER Ticket
Specify the ticket to rename.
.PARAMETER Name
Specify the principal name
.PARAMETER ServiceName
Specify a service name of type SRV_INST.
.PARAMETER Realm
Specify the realm
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicket
#>
function Rename-KerberosTicket {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicket]$Ticket,
        [Parameter(Mandatory, Position = 1)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]$Name,
        [string]$Realm
    )

    if ("" -eq $Realm) {
        $Realm = $Ticket.Realm
    }

    [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicket]::Create($Realm, $Name, $Ticket.EncryptedData)
}

<#
.SYNOPSIS
Creates a new Kerberos error.
.DESCRIPTION
This cmdlet creates a new Kerberos error authentication token.
.PARAMETER ErrorCode
Specify error code.
.PARAMETER ServerName
Specify the server principal name
.PARAMETER ServerRealm
Specify the server realm.
.PARAMETER ServerTime
Specify the server time.
.PARAMETER ServerUsec
Specify the server usecs.
.PARAMETER ClientName
Specify the client principal name.
.PARAMETER ClientRealm
Specify the client realm.
.PARAMETER ClientTime
Specify the client time.
.PARAMETER ClientUsec
Specify the client usecs.
.PARAMETER ErrorText
Specify the error text.
.PARAMETER ErrorData
Specify the error data.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosErrorAuthenticationToken
#>
function New-KerberosError {
    [CmdletBinding(DefaultParameterSetName="FromBytes")]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosErrorType]$ErrorCode,
        [Parameter(Mandatory, Position = 1)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]$ServerName,
        [Parameter(Mandatory, Position = 2)]
        [string]$ServerRealm,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTime]$ServerTime,
        [int]$ServerUsec = 0,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]$ClientName,
        [string]$ClientRealm,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTime]$ClientTime,
        [System.Nullable[int]]$ClientUsec,
        [string]$ErrorText,
        [Parameter(ParameterSetName="FromBytes")]
        [byte[]]$ErrorData,
        [Parameter(Mandatory, Position = 3, ParameterSetName="FromErrorData")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosErrorData]$ErrorDataValue,
        [switch]$NoWrapper
    )

    if ($ServerTime -eq $null) {
        $ServerTime = [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTime]::Now
    }

    if ($PSCmdlet.ParameterSetName -eq "FromErrorData") {
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosErrorAuthenticationToken]::Create($ServerTime, $ServerUsec,
            $ErrorCode, $ServerRealm, $ServerName, $ErrorDataValue, $ClientTime, $ClientUsec, $ClientRealm, $ClientName, $ErrorText,
            $NoWrapper)
    } else {
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosErrorAuthenticationToken]::Create($ServerTime, $ServerUsec,
            $ErrorCode, $ServerRealm, $ServerName, $ClientTime, $ClientUsec, $ClientRealm, $ClientName, $ErrorText, $ErrorData,
            $NoWrapper)
    }
}

<#
.SYNOPSIS
Add a Kerberos KDC pin.
.DESCRIPTION
This cmdlet adds a Kerberos KDC pin to always call a specific KDC for a realm. Only applies the pin to the current thread.
.PARAMETER Realm
Specify the realm.
.PARAMETER Hostname
Specify the hostname of the KDC.
.INPUTS
None
.OUTPUTS
None
#>
function Add-KerberosKdcPin {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Realm,
        [Parameter(Mandatory, Position = 1)]
        [string]$Hostname
    )
    [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::PinKdc($Realm, $Hostname, 0)
}

<#
.SYNOPSIS
Clear all Kerberos KDC pins.
.DESCRIPTION
This cmdlet clears all Kerberos KDC pin for the current thread.
.INPUTS
None
.OUTPUTS
None
#>
function Clear-KerberosKdcPin {
    [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::UnpinAllKdcs()
}

<#
.SYNOPSIS
Create a new AS-REQ object.
.DESCRIPTION
This cmdlet creates a new AS-REQ object for sending to a KDC.
.PARAMETER Realm
Specify the realm.
.PARAMETER ClientName
Specify the client name for the ticket.
.PARAMETER ServerName
Specify the server name for the ticket.
.PARAMETER EncryptionType
Specify a list of encryption types for the requested ticket.
.PARAMETER Forwardable
Specify to request a forwardable ticket.
.PARAMETER Canonicalize
Specify to canonicalize names.
.PARAMETER Renewable
Specify to request a renewable ticket.
.PARAMETER Password
Specify the user's password.
.PARAMETER Certificate
Specify the user's certificate.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosASRequest
#>
function New-KerberosAsRequest {
    [CmdletBinding(DefaultParameterSetName="FromKey")]
    Param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromKey")]
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromKeyWithName")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$Key,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromPassword")]
        [NtObjectManager.Utils.PasswordHolder]$Password,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromCertificate")]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory, Position = 1, ParameterSetName="FromKeyWithName")]
        [Parameter(Mandatory, Position = 1, ParameterSetName="FromPassword")]
        [Parameter(Position = 1, ParameterSetName="FromCertificate")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]$ClientName,
        [Parameter(Mandatory, Position = 2, ParameterSetName="FromKeyWithName")]
        [Parameter(Mandatory, Position = 2, ParameterSetName="FromPassword")]
        [Parameter(Position = 2, ParameterSetName="FromCertificate")]
        [string]$Realm,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromCredential")]
        [NtCoreLib.Win32.Security.Authentication.UserCredentials]$Credential,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromReadCredential")]
        [switch]$ReadCredential,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]$ServerName,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosEncryptionType[]]$EncryptionType,
        [switch]$Forwardable,
        [switch]$Canonicalize,
        [switch]$Renewable
    )

    $req = switch($PSCmdlet.ParameterSetName) {
        "FromKey" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosASRequest]::new($Key)
        }
        "FromKeyWithName" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosASRequest]::new($Key, $ClientName, $Realm)
        }
        "FromPassword" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosASRequestPassword]::new($Password.ToPlainText(), $ClientName, $Realm)
        }
        "FromCertificate" {
            if ($null -eq $ClientName -and "" -eq $Realm) {
                [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosASRequestCertificate]::new($Certificate)
            } else {
                [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosASRequestCertificate]::new($Certificate, $ClientName, $Realm)
            }
        }
        "FromCredential" {
            New-KerberosAsRequest -Password $Credential.Password -ClientName $Credential.UserName -Realm $Credential.Domain
        }
        "FromReadCredential" {
            $Credential = Read-LsaCredential
            New-KerberosAsRequest -Password $Credential.Password -ClientName $Credential.UserName -Realm $Credential.Domain
        }
    }

    if ($null -eq $req) {
        return
    }

    if ($null -ne $EncryptionType) {
        $req.EncryptionTypes.AddRange($EncryptionType)
    }

    $req.ServerName = $ServerName
    $req.Forwardable = $Forwardable
    $req.Canonicalize = $Canonicalize
    $req.Renewable = $Renewable
    $req
}

<#
.SYNOPSIS
Create a new TGS-REQ object.
.DESCRIPTION
This cmdlet creates a new TGS-REQ object for sending to a KDC.
.PARAMETER Realm
Specify the realm.
.PARAMETER ServerName
Specify the server name for the ticket.
.PARAMETER Credential
Specify the credentials for the TGS request. This could be a TGT or a service ticket for renewal.
.PARAMETER Renew
Specify to make the request renew the credential.
.PARAMETER EncryptionType
Specify a list of encryption types for the requested ticket.
.PARAMETER Forwardable
Specify to request a forwardable ticket.
.PARAMETER Canonicalize
Specify to canonicalize names.
.PARAMETER Renewable
Specify to request a renewable ticket.
.PARAMETER S4U2Proxy
Specify an existing S4U2Self ticket to create an S4U2Proxy ticket
.PARAMETER S4UUserName
Specify the user name for an S4U2Self ticket.
.PARAMETER EncryptTicketInSessionKey
Specify to encrypt the ticket using the session key from another ticket.
.PARAMETER AdditionalTicket
Specify additional tickets. Typically used with EncryptTicketInSessionKey.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosTGSRequest
#>
function New-KerberosTgsRequest {
    [CmdletBinding(DefaultParameterSetName="Create")]
    Param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="Create")]
        [Parameter(Mandatory, Position = 0, ParameterSetName="Renew")]
        [Parameter(Mandatory, Position = 0, ParameterSetName="S4U2Self")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosCredential]$Credential,
        [Parameter(Mandatory, Position = 1, ParameterSetName="Create")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]$ServerName,
        [Parameter(Mandatory, Position = 2, ParameterSetName="Create")]
        [Parameter(Mandatory, ParameterSetName="S4U2Self")]
        [string]$Realm,
        [Parameter(ParameterSetName="Create")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicket]$S4U2Proxy,
        [Parameter(Mandatory, ParameterSetName="Renew")]
        [switch]$Renew,
        [Parameter(Mandatory, ParameterSetName="S4U2Self")]
        [string]$S4UUserName,
        [switch]$EncryptTicketInSessionKey,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosEncryptionType[]]$EncryptionType,
        [switch]$Forwardable,
        [switch]$Canonicalize,
        [switch]$Renewable,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosTicket[]]$AdditionalTicket
    )

    $tgs = switch($PSCmdlet.ParameterSetName) {
        "Create" {
            if ($S4U2Proxy -eq $null) {
                [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosTGSRequest]::Create($Credential, $ServerName, $Realm)
            } else {
                [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosTGSRequest]::CreateForS4U2Proxy($Credential, $ServerName, $Realm, $S4U2Proxy)
            }
        }
        "Renew" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosTGSRequest]::CreateForRenewal($Credential)
        }
        "S4U2Self" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosTGSRequest]::CreateForS4U2Self($Credential, $S4UUserName, $Realm, $EncryptTicketInSessionKey)
        }
    }

    if ($null -ne $EncryptionType) {
        $tgs.EncryptionTypes.AddRange($EncryptionType)
    }
    if ($null -ne $AdditionalTicket) {
        foreach($t in $AdditionalTicket) {
            $tgs.AddAdditionalTicket($t)
        }
    }
    $tgs.Forwardable = $Forwardable
    $tgs.Canonicalize = $Canonicalize
    $tgs.Renewable = $Renewable
    $tgs.EncryptTicketInSessionKey = $EncryptTicketInSessionKey
    $tgs
}

<#
.SYNOPSIS
Send a Kerberos KDC request.
.DESCRIPTION
This cmdlet sends a request on the KDC for a KDC-REQ object.
.PARAMETER Hostname
Specify the hostname of the KDC.
.PARAMETER Port
Specify the port of the KDC.
.PARAMETER Request
Specify the request to send.
.PARAMETER AsExternalTicket
Specify to return as an KerberosExternalTicket
.PARAMETER AsKdcReply
Specify to return the raw reply.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosCredential
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosExternalTicket
NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosKdcReply
#>
function Send-KerberosKdcRequest {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosKDCRequest]$Request,
        [string]$Hostname,
        [int]$Port = 88,
        [switch]$AsExternalTicket,
        [switch]$AsKdcReply
    )
    $client = [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosKDCClient]::CreateTCPClient($Hostname, $Port)
    $reply = if ($Request -is [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosTGSRequest]) {
        $client.RequestServiceTicket($Request)
    } elseif ($Request -is [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosASRequestBase]) {
        $client.Authenticate($Request)
    } else {
        throw "Unknown KDC request type."
    }
    if ($null -ne $reply) {
        if($AsKdcReply) {
            $reply
        } elseif ($AsExternalTicket) {
            $reply.ToExternalTicket()
        } else {
            $reply.ToCredential()
        }
    }
}

<#
.SYNOPSIS
Create a new test Kerberos KDC server.
.DESCRIPTION
This cmdlet configures and creates a new KDC test server. You should call Start on the returned server when you want to use it.
.PARAMETER Realm
Specify the KDC's default realm.
.PARAMETER DomainSid
Specify the KDC's domain SID.
.PARAMETER Address
Specify the address to listen on.
.PARAMETER Port
Specify the TCP port to listen on.
.PARAMETER User
Specify the users hosted by the KDC.
.PARAMETER AdditionalKey
Specify additional service keys.
.PARAMETER KrbTgtKey
Specify optional krbtgt key.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.Server.KerberosKDCServer
#>
function New-KerberosKdcServer {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Realm,
        [NtCoreLib.Security.Authorization.Sid]$DomainSid,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.Server.KerberosKDCServerUser[]]$User,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey[]]$AdditionalKey,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$KrbTgtKey,
        [ipaddress]$Address = [ipaddress]::Loopback,
        [int]$Port = 88
    )

    $config = [NtCoreLib.Win32.Security.Authentication.Kerberos.Server.KerberosKDCServerConfig]::new()
    $config.Realm = $Realm
    $config.DomainSid = $DomainSid
    $config.Listener = [NtCoreLib.Win32.Security.Authentication.Kerberos.Server.KerberosKDCServerListenerTCP]::new($Address, $Port)
    if ($User -ne $null) {
        $config.Users.AddRange($User)
    }
    if ($AdditionalKey -ne $null) {
        $config.AdditionalKeys.AddRange($AdditionalKey)
    }
    $config.KrbTgtKey = $KrbTgtKey
    $config.Create()
}

<#
.SYNOPSIS
Create a new test Kerberos KDC user.
.DESCRIPTION
This cmdlet configures and creates a new KDC user.
.PARAMETER Username
Specify the user's name.
.PARAMETER UserId
Specify the user's domain RID.
.PARAMETER Key
Specify the user's keys.
.PARAMETER GroupId
Specify the user's group IDs.
.PARAMETER PrimaryGroupId
Specify the user's primary group ID.
.PARAMETER ServicePrincipalName
Specify the user's service principal names.
.PARAMETER ExtraSid
Specify the user's extra SIDs.
.PARAMETER AuthorizationData
Specify the user's authorization data.
.PARAMETER ResourceGroupDomainSid
Specify the user's resource group domain SID.
.PARAMETER ResourceGroupId
Specify the user's resource group IDs.
.PARAMETER UserAccountControlFlag
Specify the user's account control flags.
.PARAMETER
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.Server.KerberosKDCServerUser
#>
function New-KerberosKdcServerUser {
    [CmdletBinding(DefaultParameterSetName="FromPassword")]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Username,
        [Parameter(Mandatory, Position = 1)]
        [uint32]$UserId,
        [Parameter(Mandatory, Position = 2, ParameterSetName="FromPassword")]
        [AllowEmptyString()]
        [string]$Password,
        [Parameter(Mandatory, Position = 2, ParameterSetName="FromKeys")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey[]]$Key,
        [NtCoreLib.Security.Authorization.Sid]$DomainSid,
        [uint32[]]$GroupId,
        [uint32]$PrimaryGroupId = 513,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosPrincipalName[]]$ServicePrincipalName,
        [NtCoreLib.Security.Authorization.Sid[]]$ExtraSid,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthorizationData[]]$AuthorizationData,
        [NtCoreLib.Security.Authorization.Sid]$ResourceGroupDomainSid,
        [uint32[]]$ResourceGroupId,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.UserAccountControlFlags]$UserAccountControlFlag = "NormalAccount"
    )
    $user = [NtCoreLib.Win32.Security.Authentication.Kerberos.Server.KerberosKDCServerUser]::new($username)
    $user.UserId = $UserId
    switch($PSCmdlet.ParameterSetName) {
        "FromPassword" {
            $user.Password = $Password
        }
        "FromKeys" {
            $user.Keys.AddRange($Key)
        }
    }
    $user.DomainSid = $DomainSid
    foreach($rid in $GroupId) {
        $user.AddGroupId($rid)
    }
    $user.PrimaryGroupId = $PrimaryGroupId
    foreach($spn in $ServicePrincipalName) {
        $user.ServicePrincipalNames.Add($spn) | Out-Null
    }
    foreach ($sid in $ExtraSid) {
        $attr = "Mandatory, Enabled, EnabledByDefault"
        if (Test-NtSid $sid -Integrity) {
            $attr = "Integrity, IntegrityEnabled"
        }
        $user.AddExtraSid($sid, $attr)
    }
    if ($AuthorizationData -ne $null) {
        $user.AuthorizationData.AddRange($AuthorizationData)
    }
    if ($ResourceGroupDomainSid -ne $null -and $ResourceGroupId -ne $null) {
        $user.ResourceGroupDomainSid = $ResourceGroupDomainSid
        foreach($rid in $ResourceGroupId) {
            $user.AddResourceGroupId($rid)
        }
    }
    $user.UserAccountControlFlags = $UserAccountControlFlag
    $user
}

<#
.SYNOPSIS
Create a new Kerberos authorization data value.
.DESCRIPTION
This cmdlet a new Kerberos authorization data value.
.PARAMETER SecurityContext
Specify to create a KERB-LOCAL  authorization data.
.PARAMETER AuthorizationData
Specify to create a AD-IF-RELEVANT authorization data.
.PARAMETER RestrictionFlag
Specify the flags for a KERB-AD-RESTRICTION-ENTRY authorization data.
.PARAMETER IntegrityLevel
Specify the integrity level for a KERB-AD-RESTRICTION-ENTRY authorization data.
.PARAMETER MachineId
Specify the machine ID for a KERB-AD-RESTRICTION-ENTRY authorization data.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthorizationData
#>
function New-KerberosAuthorizationData {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="IfRelevant")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthorizationData[]]$AuthorizationData,
        [Parameter(Mandatory, ParameterSetName="KerbLocal")]
        [byte[]]$SecurityContext,
        [Parameter(Mandatory, ParameterSetName="KerbRest")]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosRestrictionEntryFlags]$RestrictionFlag,
        [Parameter(Mandatory, ParameterSetName="KerbRest")]
        [NtCoreLib.TokenIntegrityLevel]$IntegrityLevel,
        [Parameter(Mandatory, ParameterSetName="KerbRest")]
        [byte[]]$MachineId
    )
    switch($PSCmdlet.ParameterSetName) {
        "IfRelevant" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthorizationDataIfRelevant]::new($AuthorizationData)
        }
        "KerbLocal" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthorizationDataKerbLocal]::new($SecurityContext)
        }
        "KerbRest" {
            [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthorizationDataRestrictionEntry]::new($RestrictionFlag, $IntegrityLevel, $MachineId)
        }
    }
}

<#
.SYNOPSIS
Tries to resolve a list of KDC services for a realm.
.DESCRIPTION
This cmdlet uses DNS to query the list of KDC services for a realm.
.PARAMETER Realm
Specify the realm to query for.
.PARAMETER DnsServerAddress
Specify the address of the DNS server.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Dns.DnsServiceRecord[]
#>
function Resolve-KerberosKdcAddress {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position=0)]
        [string]$Realm,
        [System.Net.IPAddress]$DnsServerAddress
    )

    [NtCoreLib.Win32.Security.Authentication.Kerberos.Client.KerberosKDCClient]::QueryKdcForRealm($Realm, $DnsServerAddress) | Write-Output
}

<#
.SYNOPSIS
Export a Kerberos ticket/credential.
.DESCRIPTION
This cmdlet exports a kerberos ticket/credential to a file or bytes.
.PARAMETER Credential
Specify the Kerberos credential.
.PARAMETER Path
Specify the path.
.PARAMETER Base64
Specify to export as base64.
.PARAMETER InsertLineBreaks
Specify to insert line breaks in the base64.
.PARAMETER Key
Specify a key to encrypt the credential.
.INPUTS
None
.OUTPUTS
string
#>
function Export-KerberosTicket {
    [CmdletBinding(DefaultParameterSetName="ToFile")]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosCredential]$Credential,
        [Parameter(Mandatory, Position = 1, ParameterSetName="ToFile")]
        [string]$Path,
        [Parameter(Mandatory, ParameterSetName="ToBase64")]
        [switch]$Base64,
        [Parameter(ParameterSetName="ToBase64")]
        [switch]$InsertLineBreaks,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$Key
    )

    if ($null -ne $Key) {
        $Credential = $Credential.Encrypt($Key)
    }
    $ba = $Credential.ToArray()

    if ($PSCmdlet.ParameterSetName -eq "ToFile") {
        Write-BinaryFile -Path $Path -Byte $ba
    } else {
        $flags = if ($InsertLineBreaks) {
            [System.Base64FormattingOptions]::InsertLineBreaks
        } else {
            [System.Base64FormattingOptions]::None
        }
        [Convert]::ToBase64String($ba, $flags)
    }
}

<#
.SYNOPSIS
Import a Kerberos ticket/credential.
.DESCRIPTION
This cmdlet imports a kerberos ticket/credential from a file or bytes.
.PARAMETER Credential
Specify the Kerberos credential.
.PARAMETER Path
Specify the path.
.PARAMETER Base64
Specify to export as base64.
.PARAMETER Key
Specify a key to decrypt the credential.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosCredential
#>
function Import-KerberosTicket {
    [CmdletBinding(DefaultParameterSetName="FromFile")]
    Param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromFile")]
        [string]$Path,
        [Parameter(Mandatory, ParameterSetName="FromBase64")]
        [string]$Base64,
        [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$Key
    )

    $ba = if ($PSCmdlet.ParameterSetName -eq "FromFile") {
        Read-BinaryFile -Path $Path
    } else {
        [Convert]::FromBase64String($Base64)
    }

    if ($null -eq $ba) {
        return
    }

    $cred = [NtCoreLib.Win32.Security.Authentication.Kerberos.KerberosCredential]::Parse($ba)
    if ($null -eq $cred) {
        return
    }
    
    if ($Key -ne $null) {
        $cred.Decrypt($Key)
    } else {
        $cred
    }
}