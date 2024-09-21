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

function Format-ObjectTable {
    Param(
        [parameter(Mandatory, Position = 0)]
        $InputObject,
        [switch]$HideTableHeaders,
        [switch]$NoTrailingLine
    )

    $output = $InputObject | Format-Table -HideTableHeaders:$HideTableHeaders | Out-String
    $output -Split "`r`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Write-Output
    if (!$NoTrailingLine) {
        Write-Output ""
    }
}

<#
.SYNOPSIS
Get API set entries
.DESCRIPTION
This cmdlet gets API set entries for the current system.
.PARAMETER Name
Specify an API set name to lookup.
.PARAMETER Path
Specify a path to the API set file rather than using the current system's.
.PARAMETER AsNamespace
Specify to return the namespace object rather than the entries.
.INPUTS
None
.OUTPUTS
NtCoreLib.Image.ApiSet.ApiSetEntry[]
.EXAMPLE
Get-NtApiSet
Get all API set entries.
.EXAMPLE
Get-NtApiSet -Name "api-ms-win-base-util-l1-1-0"
Get an API set by name.
#>
function Get-NtApiSet {
    [CmdletBinding(DefaultParameterSetName="All")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName="FromName")]
        [string]$Name,
        [string]$Path,
        [parameter(ParameterSetName="All")]
        [switch]$AsNamespace
    )

    try {
        $apiset = if ($Path -ne "") {
            $Path = Resolve-Path -LiteralPath $Path
            [NtCoreLib.Image.ApiSet.ApiSetNamespace]::FromPath($Path)
        } else {
            [NtCoreLib.Image.ApiSet.ApiSetNamespace]::Current
        }

        if ($PSCmdlet.ParameterSetName -eq "FromName") {
            $apiset.GetApiSet($Name)
        } else {
            if ($AsNamespace) {
                $apiset
            } else {
                $apiset.Entries | Write-Output
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get the SDK name for an enumerated type or other type.
.DESCRIPTION
This cmdlet removes a package SID from the list of granted loopback exceptions.
.PARAMETER InputObject
The package SID to remove.
.INPUTS
object
.OUTPUTS
string
.EXAMPLE
Get-NtAccessMask 0x1 -AsSpecificAccess File | Get-NtSDKName
Get the SDK names for an access mask.
#>
function Get-NtSDKName { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        $InputObject
    )
    PROCESS {
        [NtCoreLib.Utilities.Reflection.ReflectionUtils]::GetSDKName($InputObject)
    }
}

<#
.SYNOPSIS
Converts a text hexdump into bytes.
.DESCRIPTION
This cmdlet tries to convert a hexdump into the original bytes.
.PARAMETER Hex
The hex dump.
.INPUTS
string
.OUTPUTS
byte[]
.EXAMPLE
1, 2, 3, 4 | Format-HexDump | ConvertFrom-HexDump
Convert some bytes to a hex dump and back again.
#>
function ConvertFrom-HexDump { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [string]$Hex
    )

    PROCESS {
        [NtCoreLib.Utilities.Text.HexDumpBuilder]::ParseHexDump($Hex)
    }
}

<#
.SYNOPSIS
Gets a certificate object.
.DESCRIPTION
This cmdlet gets a certificate object from a path.
.PARAMETER Path
Specify the path to the certificate or file. Can only be a cert:\ drive path.
.PARAMETER Pin
Specify the PIN for the certificate's private key if needed.
.PARAMETER Byte
Specify the certificate as bytes.
.INPUTS
None
.OUTPUTS
System.Security.Cryptography.X509Certificates.X509Certificate2
#>
function Get-X509Certificate {
    [CmdletBinding(DefaultParameterSetName="FromPath")]
    param(
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromPath")]
        [string]$Path,
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromByte")]
        [byte[]]$Byte,
        [NtObjectManager.Utils.PasswordHolder]$Pin
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromPath" {
            $Path = Resolve-Path -Path $Path
            if ($null -ne $Path) {
                $cert = Get-Item $Path
                if ($cert -is [Security.Cryptography.X509Certificates.X509Certificate]) {
                    [Security.Cryptography.X509Certificates.X509Certificate2]::new($cert)
                } elseif ($Pin -eq $null) {
                    [Security.Cryptography.X509Certificates.X509Certificate2]::new($Path)
                } else {
                    [Security.Cryptography.X509Certificates.X509Certificate2]::new($Path, $Pin.Password)
                }
            }
        }
        "FromByte" {
            if ($Pin -eq $null) {
                [Security.Cryptography.X509Certificates.X509Certificate2]::new($Byte)
            } else {
                [Security.Cryptography.X509Certificates.X509Certificate2]::new($Byte, $Pin.Password)
            }
        }
    }
}

<#
.SYNOPSIS
Waits on an async task and gets the result.
.DESCRIPTION
This cmdlet waits on a .net asynchronous task and returns any result.
.PARAMETER Task
Specify the asynchronous task to wait on.
.PARAMETER TimeoutSec
Specify the timeout in seconds to wait for.
.INPUTS
None
.OUTPUTS
object
.EXAMPLE
Wait-AsyncTaskResult -Task $task
Wait on the task and result.
.EXAMPLE
Wait-AsyncTaskResult -Task $task -TimeoutSec 10
Wait on the task and result for up to 10 seconds.
#>
function Wait-AsyncTaskResult {
    Param(
        [parameter(Mandatory, Position = 0)]
        [System.Threading.Tasks.Task]$Task,
        [int]$TimeoutSec = [int]::MaxValue
    )

    while (-not $Task.Wait(1000)) {
        $TimeoutSec--
        if ($TimeoutSec -le 0) {
            return
        }
    }

    $Task.GetAwaiter().GetResult() | Write-Output
}

<#
.SYNOPSIS
Formats a hex dump for a byte array.
.DESCRIPTION
This cmdlet converts a byte array to a hex dump string. If invoked as Out-HexDump will write the to the console.
.PARAMETER Bytes
The bytes to convert.
.PARAMETER ShowHeader
Display a header for the hex dump.
.PARAMETER ShowAddress
Display the address for the hex dump.
.PARAMETER ShowAscii
Display the ASCII dump along with the hex.
.PARAMETER HideRepeating
Hide repeating 16 byte patterns.
.PARAMETER Buffer
Show the contents of a safe buffer.
.PARAMETER Offset
Specify start offset into the safe buffer or the file.
.PARAMETER Length
Specify length of safe buffer or the file.
.PARAMETER BaseAddress
Specify base address for the display when ShowAddress is enabled.
.INPUTS
byte[]
.OUTPUTS
String
#>
function Format-HexDump {
    [CmdletBinding(DefaultParameterSetName = "FromBytes")]
    Param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ParameterSetName = "FromBytes")]
        [Alias("Bytes")]
        [AllowEmptyCollection()]
        [byte[]]$Byte,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromFile")]
        [string]$Path,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromBuffer")]
        [System.Runtime.InteropServices.SafeBuffer]$Buffer,
        [Parameter(ParameterSetName = "FromBuffer")]
        [Parameter(ParameterSetName = "FromFile")]
        [int64]$Offset = 0,
        [Parameter(ParameterSetName = "FromBuffer")]
        [Parameter(ParameterSetName = "FromFile")]
        [int64]$Length = 0,
        [Parameter(ParameterSetName = "FromBytes")]
        [int64]$BaseAddress = 0,
        [switch]$ShowHeader,
        [switch]$ShowAddress,
        [switch]$ShowAscii,
        [switch]$ShowAll,
        [switch]$HideRepeating
    )

    BEGIN {
        if ($ShowAll) {
            $ShowHeader = $true
            $ShowAscii = $true
            $ShowAddress = $true
        }

        $WriteToHost = $PSCmdlet.MyInvocation.InvocationName -eq "Out-HexDump"

        switch ($PSCmdlet.ParameterSetName) {
            "FromBytes" {
                $builder = [NtCoreLib.Utilities.Text.HexDumpBuilder]::new($ShowHeader, $ShowAddress, $ShowAscii, $HideRepeating, $BaseAddress);
            }
            "FromBuffer" {
                $builder = [NtCoreLib.Utilities.Text.HexDumpBuilder]::new($Buffer, $Offset, $Length, $ShowHeader, $ShowAddress, $ShowAscii, $HideRepeating);
            }
            "FromFile" {
                $builder = [NtCoreLib.Utilities.Text.HexDumpBuilder]::new($ShowHeader, $ShowAddress, $ShowAscii, $HideRepeating, $Offset);
            }
        }
    }

    PROCESS {
        switch ($PSCmdlet.ParameterSetName) {
            "FromBytes" {
                $builder.Append($Byte)
            }
            "FromFile" {
                $Path = Resolve-Path $Path -ErrorAction Stop
                $builder.AppendFile($Path, $Offset, $Length)
            }
        }
    }

    END {
        $builder.Complete()
        $output = $builder.ToString()
        if ($WriteToHost) {
            $output | Write-Host
        } else {
            $output | Write-Output
        }
    }
}

Set-Alias -Name Out-HexDump -Value Format-HexDump

<#
.SYNOPSIS
Get a service principal name.
.DESCRIPTION
This cmdlet gets SPN for a string.
.PARAMETER Name
Specify the SPN.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Authentication.ServicePrincipalName
.EXAMPLE
Get-ServicePrincipalName -Name "HTTP/www.domain.com"
Get the SPN from a string.
#>
function Get-ServicePrincipalName {
    param (
        [parameter(Mandatory, Position = 0)]
        [string]$Name
    )
    [NtCoreLib.Win32.Security.Authentication.ServicePrincipalName]::Parse($Name) | Write-Output
}

<#
.SYNOPSIS
Get a MD4 hash of a byte array or string.
.DESCRIPTION
This cmdlet calculates the MD4 hash of a byte array or string.
.PARAMETER Bytes
Specify a byte array.
.PARAMETER String
Specify string.
.PARAMETER Encoding
Specify string encoding. Default to Unicode.
.INPUTS
None
.OUTPUTS
byte[]
.EXAMPLE
Get-MD4Hash -String "ABC"
Get the MD4 hash of the string ABC in unicode.
.EXAMPLE
Get-MD4Hash -String "ABC" -Encoding "ASCII"
Get the MD4 hash of the string ABC in ASCII.
.EXAMPLE
Get-MD4Hash -Bytes @(0, 1, 2, 3)
Get the MD4 hash of a byte array.
#>
function Get-MD4Hash {
    [CmdletBinding(DefaultParameterSetName="FromString")]
    Param(
        [AllowEmptyString()]
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromString")]
        [string]$String,
        [Parameter(Position = 1, ParameterSetName="FromString")]
        [string]$Encoding = "Unicode",
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromBytes")]
        [byte[]]$Bytes
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromString" {
            $enc = [System.Text.Encoding]::GetEncoding($Encoding)
            [NtCoreLib.Utilities.Security.Cryptography.MD4]::CalculateHash($String, $enc)
        }
        "FromBytes" {
            [NtCoreLib.Utilities.Security.Cryptography.MD4]::CalculateHash($Bytes)
        }
    }
}

<#
.SYNOPSIS
Formats ASN.1 DER data to a string.
.DESCRIPTION
This cmdlet formats ASN.1 DER data to a string either from a byte array or a file.
.PARAMETER Byte
Specify a byte array containing the DER data.
.PARAMETER Path
Specify file containing the DER data.
.PARAMETER Depth
Specify initialize indentation depth.
.INPUTS
None
.OUTPUTS
string
.EXAMPLE
Format-ASN1DER -Byte $ba
Format the byte array with ASN.1 DER data.
.EXAMPLE
Format-ASN1DER -Byte $ba -Depth 2
Format the byte array with ASN.1 DER data with indentation depth of 2.
.EXAMPLE
Format-ASN1DER -Path file.bin
Format the file containing ASN.1 DER data.
#>
function Format-ASN1DER {
    [CmdletBinding(DefaultParameterSetName="FromBytes")]
    Param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromPath")]
        [string]$Path,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromBytes")]
        [byte[]]$Byte,
        [int]$Depth = 0
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromPath" {
            [NtCoreLib.Utilities.ASN1.ASN1Utils]::FormatDER($Path, $Depth)
        }
        "FromBytes" {
            [NtCoreLib.Utilities.ASN1.ASN1Utils]::FormatDER($Byte, $Depth)
        }
    }
}

<#
.SYNOPSIS
Parses ASN.1 DER data to objects.
.DESCRIPTION
This cmdlet parses ASN.1 DER data into an object model.
.PARAMETER Byte
Specify a byte array containing the DER data.
.PARAMETER Path
Specify file containing the DER data.
.INPUTS
None
.OUTPUTS
NtCoreLib.Utilities.ASN1.Parser.ASN1Object
.EXAMPLE
Get-ASN1DER -Bytes $ba
Parse the byte array into ASN.1 DER data objects.
#>
function Get-ASN1DER {
    [CmdletBinding(DefaultParameterSetName="FromBytes")]
    Param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromPath")]
        [string]$Path,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromBytes")]
        [byte[]]$Byte,
        [int]$Depth = 0
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromPath" {
            [NtCoreLib.Utilities.ASN1.ASN1Utils]::ParseDER($Path)
        }
        "FromBytes" {
            [NtCoreLib.Utilities.ASN1.ASN1Utils]::ParseDER($Byte)
        }
    }
}

<#
.SYNOPSIS
Creates a new ASN.1 DER builder.
.DESCRIPTION
This cmdlet creates a new ASN.1 DER builder object which can be used to create DER encoded data.
.INPUTS
None
.OUTPUTS
NtCoreLib.Utilities.ASN1.Builder.DERBuilder
.EXAMPLE
New-ASN1DER
Creates a new ASN.1 DER builder.
#>
function New-ASN1DER {
    [NtCoreLib.Utilities.ASN1.Builder.DERBuilder]::new()
}

<#
.SYNOPSIS
Split a command line into its component parts.
.DESCRIPTION
This cmdlet take a process command line and split it into its component parts.
.PARAMETER CommandLine
The command line.
.INPUTS
None
.OUTPUTS
string[]
.EXAMPLE
Split-Win32CommandLine -CommandLine "notepad test.txt"
Split the command line "notepad test.txt"
#>
function Split-Win32CommandLine {
    Param(
        [parameter(Position = 0, Mandatory)]
        [string]$CommandLine
    )
    [NtCoreLib.Win32.Process.Win32ProcessUtils]::ParseCommandLine($CommandLine) | Write-Output
}

# We use this incase we're running on a downlevel PowerShell.
function Get-IsPSCore {
    return ($PSVersionTable.Keys -contains "PSEdition") -and ($PSVersionTable.PSEdition -ne 'Desktop')
}

<#
.SYNOPSIS
Protect a byte array using RC4.
.DESCRIPTION
This cmdlet used the RC4 encryption algorithm to protect a byte array. Note as encryption
and decryption are symmetrical this function process encrypts and decrypts. Note this 
returns the encrypted data, it doesn't encrypt place.
.PARAMETER Data
The bytes to encrypt.
.PARAMETER Key
The key to use.
.PARAMETER Offset
The offset into the data to unprotect. Defaults to the start of the data.
.PARAMETER Length
The length of the data to unprotect. Defaults to all remaining data.
.INPUTS
None
.OUTPUTS
byte[]
.EXAMPLE
Protect-RC4 -Byte @(0, 1, 2, 3) -Key @(4, 7, 1, 254)
Protect the byte array with RC4.
#>
function Protect-RC4 {
    Param(
        [Parameter(Mandatory, Position = 0)]
        [byte[]]$Data,
        [Parameter(Mandatory, Position = 1)]
        [byte[]]$Key,
        [int]$Offset = 0,
        [int]$Length = -1
    )

    if ($Length -lt 0) {
        $Length = $Data.Length - $Offset
    }
    [NtCoreLib.Utilities.Security.Cryptography.ARC4]::Transform($Data, $Offset, $Length, $Key)
}

Set-Alias -Name Unprotect-RC4 -Value Protect-RC4

<#
.SYNOPSIS
Selects strings out a binary value.
.DESCRIPTION
This cmdlet searches through a byte buffer for ASCII or Unicode strings.
.PARAMETER Bytes
Show the strings in a bytes.
.PARAMETER Buffer
Show the strings in a safe buffer.
.PARAMETER Path
Show the strings in a file.
.PARAMETER MinimumLength
Specify the minimum string length to return.
.PARAMETER Type
Specify the types of string to return. Defaults to ASCII and Unicode.
.INPUTS
byte[]
.OUTPUTS
NtCoreLib.Utilities.Text.ExtractedString
#>
function Select-BinaryString {
    [CmdletBinding(DefaultParameterSetName = "FromBytes")]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ParameterSetName = "FromBytes")]
        [Alias("Bytes")]
        [AllowEmptyCollection()]
        [byte[]]$Byte,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromFile")]
        [string]$Path,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromBuffer")]
        [System.Runtime.InteropServices.SafeBuffer]$Buffer,
        [NtCoreLib.Utilities.Text.ExtractedStringType]$Type = "Ascii, Unicode",
        [int]$MinimumLength = 3
    )

    BEGIN {
        $stm = [System.IO.MemoryStream]::new()
        $in_pipeline = $PSCmdlet.MyInvocation.PipelinePosition -eq 1
    }

    PROCESS {
        switch ($PSCmdlet.ParameterSetName) {
            "FromBytes" {
                if ($in_pipeline) {
                    $stm.Write($Byte, 0, $Byte.Length)
                } else {
                    [NtCoreLib.Utilities.Text.StringExtractor]::Extract($Byte, $MinimumLength, $Type) | Write-Output
                }
            }
            "FromBuffer" {
                [NtCoreLib.Utilities.Text.StringExtractor]::Extract($Buffer, $MinimumLength, $Type) | Write-Output
            }
            "FromFile" {
                $Path = Resolve-Path $Path -ErrorAction Stop
                [NtCoreLib.Utilities.Text.StringExtractor]::Extract($Path, $MinimumLength, $Type) | Write-Output
            }
        }
    }

    END {
        if ($stm.Length -gt 0) {
            $stm.Position = 0
            [NtCoreLib.Utilities.Text.StringExtractor]::Extract($stm, $MinimumLength, $Type) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Send a message to update the environment from the registry.
.DESCRIPTION
This cmdlet sends the WM_SETTINGCHANGE broadcast message to force explorer (and anyone else listenting)
to update their environment variables from the registry.
.INPUTS
None
.OUTPUTS
None
#>
function Update-Win32Environment {
    $str = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("Environment")
    try {
        [NtCoreLib.NtWindow]::Broadcast.SendMessage(0x1A, [System.IntPtr]::Zero, $str) | Out-Null
    } finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($str)
    }
}

function Read-BinaryFile {
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Path
    )
    $ba = if (Get-IsPSCore) {
        Get-Content -Path $Path -AsByteStream
    } else {
        Get-Content -Path $Path -Encoding Byte
    }
    [byte[]]$ba
}

function Write-BinaryFile {
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Path,
        [Parameter(Mandatory, Position = 1)]
        [byte[]]$Byte
    )
    if (Get-IsPSCore) {
        $Byte | Set-Content -Path $Path -AsByteStream
    } else {
        $Byte | Set-Content -Path $Path -Encoding Byte
    }
}