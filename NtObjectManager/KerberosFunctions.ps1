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
NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey
.OUTPUTS
None
#>
function Export-KerberosKeyTab {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Path,
        [Parameter(Position = 1, Mandatory, ValueFromPipeline)]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey[]]$Key
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
        $key_arr = [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey[]]$keys
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosUtils]::GenerateKeyTabFile($key_arr) `
                | Set-Content -Path $Path -Encoding Byte
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
NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey
#>
function Import-KerberosKeyTab {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Path
    )

    $Path = Resolve-Path -Path $Path -ErrorAction Stop
    [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosUtils]::ReadKeyTabFile($Path) | Write-Output
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
NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey
#>
function Get-KerberosKey {
    [CmdletBinding(DefaultParameterSetName="FromPassword")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromPassword")]
        [string]$Password,
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
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosEncryptionType]$KeyType,
        [Parameter(ParameterSetName="FromPassword")]
        [int]$Interations = 4096,
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosNameType]$NameType = "PRINCIPAL",
        [Parameter(Position = 2, Mandatory, ParameterSetName="FromPassword")]
        [Parameter(Position = 2, Mandatory, ParameterSetName="FromKey")]
        [Parameter(Mandatory, ParameterSetName="FromBase64Key")]
        [Parameter(Mandatory, ParameterSetName="FromHexKey")]
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
                [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]::DeriveKey($KeyType, $Password, $Interations, $NameType, $Principal, $Salt, $Version)
            }
            "FromKey" {
                [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]::new($KeyType, $Key, $NameType, $Principal, $Timestamp, $Version)
            }
            "FromBase64Key" {
                $Key = [System.Convert]::FromBase64String($Base64Key)
                [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]::new($KeyType, $Key, $NameType, $Principal, $Timestamp, $Version)
            }
            "FromHexKey" {
                $Key = ConvertFrom-HexDump -Hex $HexKey
                [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]::new($KeyType, $Key, $NameType, $Principal, $Timestamp, $Version)
            }
        }
        $k | Write-Output
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Create a new random kerbero key.
.DESCRIPTION
This cmdlet creates a new Kerberos Key.
.PARAMETER KeyType
The key encryption type.
.PARAMETER Key
The existing key to use the encryption type from.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey
#>
function New-KerberosKey {
    [CmdletBinding(DefaultParameterSetName="FromEncType")]
    Param(
        [Parameter(Mandatory, ParameterSetName="FromEncType", Position = 0)]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosEncryptionType]$KeyType,
        [Parameter(Mandatory, ParameterSetName="FromKey", Position = 0)]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$Key
    )

    if ($PSCmdlet.ParameterSetName -eq "FromKey") {
        $Key.GenerateKey()
    } else {
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]::GenerateKey($KeyType)
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
NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosExternalTicket
#>
function Get-KerberosTicket {
    [CmdletBinding(DefaultParameterSetName="CurrentLuid")]
    Param(
        [Parameter(Position = 0, ParameterSetName="FromTarget", Mandatory)]
        [Parameter(Position = 0, ParameterSetName="FromTargetCredHandle", Mandatory)]
        [Parameter(Position = 0, ParameterSetName="FromLocalCache", Mandatory)]
        [string]$TargetName,
        [Parameter(Position = 0, ParameterSetName="FromLuid", Mandatory)]
        [Parameter(Position = 1, ParameterSetName="FromTarget")]
        [NtApiDotNet.Luid]$LogonId = [NtApiDotNet.Luid]::new(0),
        [Parameter(Position = 0, ParameterSetName="FromLogonSession", ValueFromPipeline, Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.LogonSession[]]$LogonSession,
        [Parameter(ParameterSetName="FromTargetCredHandle", Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.CredentialHandle]$CredHandle,
        [Parameter(ParameterSetName="FromLocalCache", Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]$Cache,
        [Parameter(ParameterSetName="FromTarget")]
        [Parameter(ParameterSetName="FromTargetCredHandle")]
        [Parameter(ParameterSetName="FromLocalCache")]
        [switch]$CacheOnly,
        [Parameter(ParameterSetName="FromLuid")]
        [Parameter(ParameterSetName="CurrentLuid")]
        [Parameter(ParameterSetName="FromLogonSession")]
        [switch]$InfoOnly
    )

    PROCESS {
        try {
            switch($PSCmdlet.ParameterSetName) {
                "CurrentLuid" {
                    if ($InfoOnly) {
                        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCacheInfo() | Write-Output
                    } else {
                        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCache() | Write-Output
                    }
                }
                "FromLuid" {
                    if ($InfoOnly) {
                        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCacheInfo($LogonId) | Write-Output
                    } else {
                        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCache($LogonId) | Write-Output
                    }
                }
                "FromLogonSession" {
                    foreach($l in $LogonSession) {
                        if ($InfoOnly) {
                            [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCacheInfo($l.LogonId) | Write-Output
                        } else {
                            [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCache($l.LogonId) | Write-Output
                        }
                    }
                }
                "FromTarget" {
                    [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::GetTicket($TargetName, $LogonId, $CacheOnly) | Write-Output
                }
                "FromTargetCredHandle" {
                    [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::GetTicket($TargetName, $CredHandle, $CacheOnly) | Write-Output
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
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicket]$Ticket
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
NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosChecksum
#>
function New-KerberosChecksum {
    [CmdletBinding(DefaultParameterSetName="FromGssApi")]
    Param(
        [Parameter(ParameterSetName="FromGssApi")]
        [byte[]]$ChannelBinding,
        [Parameter(ParameterSetName="FromGssApi")]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosChecksumGSSApiFlags]$ContextFlags = 0,
        [Parameter(ParameterSetName="FromGssApi")]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosCredential]$Credential,
        [Parameter(ParameterSetName="FromGssApi")]
        [int]$DelegationOptionIdentifier = 0,
        [Parameter(ParameterSetName="FromGssApi")]
        [byte[]]$Extension,
        [Parameter(Mandatory, ParameterSetName="FromRaw")]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosChecksumType]$Type,
        [Parameter(Mandatory, ParameterSetName="FromRaw")]
        [byte[]]$Checksum,
        [Parameter(Mandatory, ParameterSetName="FromKey")]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$Key,
        [Parameter(Mandatory, ParameterSetName="FromKey")]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosKeyUsage]$KeyUsage,
        [Parameter(Mandatory, ParameterSetName="FromKey")]
        [byte[]]$Data
    )

    PROCESS {
        switch($PSCmdlet.ParameterSetName) {
            "FromGssApi" {
                [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosChecksumGSSApi]::new($ContextFlags, $ChannelBinding, $DelegationOptionIdentifier, $Credential, $Extension)
            }
            "FromRaw" {
                [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosChecksum]::new($Type, $Checksum)
            }
            "FromKey" {
                [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosChecksum]::Create($Key, $Data, $KeyUsage)
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
NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosPrincipalName
#>
function New-KerberosPrincipalName {
    [CmdletBinding(DefaultParameterSetName="FromName")]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosNameType]$Type,
        [Parameter(Mandatory, Position = 1, ParameterSetName = "FromName")]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName = "FromNamePart")]
        [string[]]$NamePart
    )


    switch($PSCmdlet.ParameterSetName) {
        "FromName" {
            [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]::new($Type, $Name)
        }
        "FromNamePart" {
            [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]::new($Type, $NamePart)
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
NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticator
#>
function New-KerberosAuthenticator {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$ClientRealm,
        [Parameter(Mandatory, Position = 1)]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]$ClientName,
        [datetime]$ClientTime = [datetime]::MinValue,
        [int]$ClientUSec = 0,
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosChecksum]$Checksum,
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$SubKey,
        [System.Nullable[int]]$SequenceNumber = $null,
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthorizationData[]]$AuthorizationData
    )

    if ($ClientTime -eq [datetime]::MinValue) {
        $ClientTime = [datetime]::Now
    }
    [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticator]::Create($ClientRealm, $ClientName, $ClientTime, `
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
NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAPRequestAuthenticationToken
#>
function New-KerberosAPRequest {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicket]$Ticket,
        [Parameter(Mandatory, Position = 1)]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosEncryptedData]$Authenticator,
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAPRequestOptions]$Options = 0,
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$AuthenticatorKey,
        [System.Nullable[int]]$AuthenticatorKeyVersion,
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$TicketKey,
        [System.Nullable[int]]$TicketKeyVersion,
        [switch]$RawToken
    )

    [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAPRequestAuthenticationToken]::Create($Ticket, $Authenticator, $Options, `
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
NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicket
#>
function New-KerberosTicket {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Realm,
        [Parameter(Mandatory, Position = 1)]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosPrincipalName]$ServerName,
        [Parameter(Mandatory, Position = 2)]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosEncryptedData]$EncryptedData
    )

    [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicket]::Create($Realm, $ServerName, $EncryptedData)
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
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosCredential]$Credential,
        [Parameter(ParameterSetName="FromSystem")]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$Key,
        [Parameter(ParameterSetName="FromSystem")]
        [NtApiDotNet.Luid]$LogonId = 0,
        [Parameter(ParameterSetName="FromLocalCache", Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]$Cache
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromSystem" {
            [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::SubmitTicket($Credential, $LogonId, $Key)
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
        [NtApiDotNet.Luid]$LogonId = 0,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromAll")]
        [switch]$All
    )

    [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::PurgeTicketCache($LogonId, $ServerName, $Realm)
}

<#
.SYNOPSIS
Create a new local Kerberos cache.
.DESCRIPTION
This cmdlet creates a new local Kerberos ticket cache. Defaults to populating from the current system cache.
.PARAMETER CreateClient
Create a client when initializing from the system cache.
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
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache
#>
function New-KerberosTicketCache {
    [CmdletBinding(DefaultParameterSetName="FromSystem")]
    Param(
        [Parameter(ParameterSetName="FromSystem")]
        [switch]$CreateClient,
        [Parameter(ParameterSetName="FromSystem")]
        [NtApiDotNet.Luid]$LogonId = 0,
        [Parameter(ParameterSetName="FromTgt", Mandatory, Position = 0)]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosCredential]$Credential,
        [Parameter(ParameterSetName="FromKey", Mandatory, Position = 0)]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]$Key,
        [Parameter(ParameterSetName="FromTgt")]
        [Parameter(ParameterSetName="FromKey")]
        [string]$Hostname = $env:LOGONSERVER.TrimStart('\'),
        [Parameter(ParameterSetName="FromTgt")]
        [Parameter(ParameterSetName="FromKey")]
        [int]$Port = 88,
        [Parameter(ParameterSetName="FromTgt")]
        [string]$Realm = [NullString]::Value,
        [Parameter(ParameterSetName="FromTgt")]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosExternalTicket[]]$AdditionalTicket
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromSystem" {
            [NtApiDotNet.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]::FromSystemCache($CreateClient, $LogonId)
        }
        "FromTgt" {
            $client = [NtApiDotNet.Win32.Security.Authentication.Kerberos.Client.KerberosKDCClient]::CreateTCPClient($Hostname, $Port)
            [NtApiDotNet.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]::new($Credential, $client, $Realm, $AdditionalTicket)
        }
        "FromKey" {
            $client = [NtApiDotNet.Win32.Security.Authentication.Kerberos.Client.KerberosKDCClient]::CreateTCPClient($Hostname, $Port)
            [NtApiDotNet.Win32.Security.Authentication.Kerberos.Client.KerberosLocalTicketCache]::FromClient($client, $Key)
        }
    }
}