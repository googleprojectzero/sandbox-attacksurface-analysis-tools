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
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosExternalTicket
#>
function Get-KerberosTicket {
    [CmdletBinding(DefaultParameterSetName="CurrentLuid")]
    Param(
        [Parameter(Position = 0, ParameterSetName="FromLuid", Mandatory)]
        [Parameter(ParameterSetName="FromTarget")]
        [NtApiDotNet.Luid]$LogonId = [NtApiDotNet.Luid]::new(0),
        [Parameter(Position = 0, ParameterSetName="FromLogonSession", ValueFromPipeline, Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.LogonSession[]]$LogonSession,
        [Parameter(Position = 0, ParameterSetName="FromTarget", Mandatory)]
        [Parameter(Position = 0, ParameterSetName="FromTargetCredHandle", Mandatory)]
        [string]$TargetName,
        [Parameter(ParameterSetName="FromTarget")]
        [Parameter(ParameterSetName="FromTargetCredHandle")]
        [switch]$CacheOnly,
        [Parameter(ParameterSetName="FromTargetCredHandle", Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.CredentialHandle]$CredHandle
    )

    PROCESS {
        switch($PSCmdlet.ParameterSetName) {
            "CurrentLuid" {
                [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCache() | Write-Output
            }
            "FromLuid" {
                [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCache($LogonId) | Write-Output
            }
            "FromLogonSession" {
                foreach($l in $LogonSession) {
                    [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCache($l.LogonId) | Write-Output
                }
            }
            "FromTarget" {
                [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::GetTicket($TargetName, $LogonId, $CacheOnly) | Write-Output
            }
            "FromTargetCredHandle" {
                [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::GetTicket($TargetName, $CredHandle, $CacheOnly) | Write-Output
            }
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
