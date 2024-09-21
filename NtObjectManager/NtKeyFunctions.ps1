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
Gets a list of system environment values
.DESCRIPTION
This cmdlet gets the list of system environment values. Note that this isn't the same as environment
variables, these are kernel values which represent current system state.
.PARAMETER Name
The name of the system environment value to get.
.INPUTS
None
#>
function Get-NtSystemEnvironmentValue {
    Param(
        [Parameter(Position = 0)]
        [string]$Name = [System.Management.Automation.Language.NullString]::Value
    )
    Set-NtTokenPrivilege SeSystemEnvironmentPrivilege | Out-Null
    $values = [NtCoreLib.NtSystemInfo]::QuerySystemEnvironmentValueNamesAndValues()
    if ($Name -eq [string]::Empty) {
        $values
    }
    else {
        $values | Where-Object Name -eq $Name
    }
}

<#
.SYNOPSIS
Get a license value by name.
.DESCRIPTION
This cmdlet gets a license value by name
.PARAMETER Name
The name of the license value to get.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtKeyValue
#>
function Get-NtLicenseValue {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Name
    )
    [NtCoreLib.NtKey]::QueryLicenseValue($Name)
}

<#
.SYNOPSIS
Get the values from a registry key.
.DESCRIPTION
This cmdlet will get one or more values from a registry key.
.PARAMETER Key
The base key to query the values from.
.PARAMETER Name
The name of the value to query. If not specified then returns all values.
.PARAMETER AsString
Output the values as strings.
.PARAMETER AsObject
Output the values as the data object.
.INPUTS
None
.OUTPUTS
NtKeyValue
.EXAMPLE
Get-NtKeyValue -Key $key
Get all values from a key.
.EXAMPLE
Get-NtKeyValue -Key $key -AsString
Get all values from a key as a string.
.EXAMPLE
Get-NtKeyValue -Key $key -Name ""
Get the default value from a key.
.EXAMPLE
Get-NtKeyValue -Key $key -Name MyValue
Get the MyValue value from a key.
#>
function Get-NtKeyValue {
    [CmdletBinding(DefaultParameterSetName = "FromKeyAll")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName="FromKeyAll")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromKeyName")]
        [NtCoreLib.NtKey]$Key,
        [parameter(ParameterSetName = "FromKeyName", Mandatory, Position = 1)]
        [parameter(ParameterSetName = "FromPathName", Mandatory, Position = 1)]
        [string]$Name,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromPathAll")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromPathName")]
        [string]$Path,
        [parameter(ParameterSetName = "FromPathAll")]
        [parameter(ParameterSetName = "FromPathName")]
        [switch]$Win32Path,
        [switch]$AsString,
        [switch]$AsObject
    )

    try {
        $values = switch ($PSCmdlet.ParameterSetName) {
            "FromKeyAll" {
                $Key.QueryValues()
            }
            "FromKeyName" {
                @($Key.QueryValue($Name))
            }
            "FromPathName" {
                Use-NtObject($k = Get-NtKey -Path $Path -Win32Path:$Win32Path -Access QueryValue) {
                    @($k.QueryValue($Name))
                }
            }
            "FromPathAll" {
                Use-NtObject($k = Get-NtKey -Path $Path -Win32Path:$Win32Path -Access QueryValue) {
                    $k.QueryValues()
                }
            }
        }
        if ($AsString) {
            $values | ForEach-Object { $_.ToString() } | Write-Output
        } elseif($AsObject) {
            $values | ForEach-Object { $_.ToObject() } | Write-Output
        } else {
            $values | Write-Output
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Remove a value from a registry key.
.DESCRIPTION
This cmdlet will remove one more values from a registry key.
.PARAMETER Key
The base key to remove the values from.
.PARAMETER Name
The names of the values to remove.
.INPUTS
None
.EXAMPLE
Remove-NtKeyValue -Key $key -Name ABC
Removes the value ABC from the Key.
.EXAMPLE
Remove-NtKeyValue -Key $key -Name ABC, XYZ
Removes the value ABC and XYZ from the Key.
#>
function Remove-NtKeyValue {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtKey]$Key,
        [parameter(Mandatory, Position = 1)]
        [string[]]$Name
    )
    foreach ($n in $Name) {
        $Key.DeleteValue($n)
    }
}

<#
.SYNOPSIS
Gets the list of loaded hives.
.DESCRIPTION
This cmdlet enumerates the list of loaded hives from the Registry.
.PARAMETER FormatWin32File
Format the file path to a Win32 string if possible.
.INPUTS
None
.OUTPUTS
NtKeyHive[]
.EXAMPLE
Get-NtKeyHiveSplit
Get the list of loaded hives.
.EXAMPLE
Get-NtKeyHiveSplit -FormatWin32File
Get the list of loaded hives with the file path in Win32 format.
#>
function Get-NtKeyHive {
    Param(
        [switch]$FormatWin32File
    )
    [NtCoreLib.NtKeyUtils]::GetHiveList($FormatWin32File) | Write-Output
}

<#
.SYNOPSIS
Backup a key to a file.
.DESCRIPTION
This cmdlet back ups a key to a file.
.PARAMETER Path
The path to the file to backup to.
.PARAMETER Win32Path
The path is a Win32 path.
.PARAMETER File
Specify the file to write to.
.PARAMETER Key
The key to backup.
.PARAMETER Flags
Flags for the backup operation.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Backup-NtKey -Key $key -Path \??\c:\backup.hiv
Backup the key to c:\backup.hiv
.EXAMPLE
Backup-NtKey -Key $key -Path backup.hiv -Win32Path
Backup the key to backup.hiv in the current directory.
.EXAMPLE
Backup-NtKey -Key $key -File $file
Backup the key to a file object.
#>
function Backup-NtKey {
    [CmdletBinding(DefaultParameterSetName = "FromPath")]
    Param(
        [parameter(Position = 0, Mandatory)]
        [NtCoreLib.NtKey]$Key,
        [NtCoreLib.SaveKeyFlags]$Flags = "StandardFormat",
        [parameter(Position = 1, Mandatory, ParameterSetName="FromPath")]
        [string]$Path,
        [parameter(ParameterSetName="FromPath")]
        [switch]$Win32Path,
        [parameter(Position = 1, Mandatory, ParameterSetName="FromFile")]
        [NtCoreLib.NtFile]$File
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromFile" {
            $Key.Save($File, $Flags)
        }
        "FromPath" {
            if ($Win32Path) {
                $Path = Get-NtFilePath -FullName $Path
            }
            $Key.Save($Path, $Flags)
        }
    }
}

<#
.SYNOPSIS
Restore a key from a file.
.DESCRIPTION
This cmdlet restores a key from a file.
.PARAMETER Path
The path to the file to restore from.
.PARAMETER Win32Path
The path is a Win32 path.
.PARAMETER File
Specify the file to read from.
.PARAMETER Key
The key to restore.
.PARAMETER Flags
Flags for the restore operation.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Restore-NtKey -Key $key -Path \??\c:\backup.hiv
Restore the key from c:\backup.hiv
.EXAMPLE
Restore-NtKey -Key $key -Path backup.hiv -Win32Path
Restore the key from backup.hiv in the current directory.
.EXAMPLE
Restore-NtKey -Key $key -File $file
Restore the key from a file object.
#>
function Restore-NtKey {
    [CmdletBinding(DefaultParameterSetName = "FromPath")]
    Param(
        [parameter(Position = 0, Mandatory)]
        [NtCoreLib.NtKey]$Key,
        [NtCoreLib.RestoreKeyFlags]$Flags = "None",
        [parameter(Position = 1, Mandatory, ParameterSetName="FromPath")]
        [string]$Path,
        [parameter(ParameterSetName="FromPath")]
        [switch]$Win32Path,
        [parameter(Position = 1, Mandatory, ParameterSetName="FromFile")]
        [NtCoreLib.NtFile]$File
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromFile" {
            $Key.Restore($File, $Flags)
        }
        "FromPath" {
            if ($Win32Path) {
                $Path = Get-NtFilePath -FullName $Path
            }
            $Key.Restore($Path, $Flags)
        }
    }
}
