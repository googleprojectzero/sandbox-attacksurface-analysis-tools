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
Create a new image section based on an existing file.
.DESCRIPTION
This cmdlet creates an image section based on an existing file.
.PARAMETER File
A file object to an image file to create.
.PARAMETER Path
A path to an image to create.
.PARAMETER Win32Path
Resolve path as a Win32 path
.PARAMETER ObjectPath
Specify an object path for the new section object.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtSection
.EXAMPLE
New-NtSectionImage -Path \??\c:\windows\notepad.exe
Creates a
.EXAMPLE
New-NtSectionImage -File $file
Creates a new image section from an open NtFile object.
#>
function New-NtSectionImage {
    [CmdletBinding(DefaultParameterSetName = "FromFile")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromFile", Mandatory = $true)]
        [NtCoreLib.NtFile]$File,
        [Parameter(Position = 0, ParameterSetName = "FromPath", Mandatory = $true)]
        [string]$Path,
        [Parameter(ParameterSetName = "FromPath")]
        [switch]$Win32Path,
        [string]$ObjectPath
    )

    if ($null -eq $File) {
        if ($Win32Path) {
            $Path = Get-NtFilePath $Path -Resolve
        }
        Use-NtObject($new_file = Get-NtFile -Path $Path -Share Read, Delete -Access GenericExecute) {
            return [NtCoreLib.NtSection]::CreateImageSection($ObjectPath, $new_file)
        }
    }
    else {
        return [NtCoreLib.NtSection]::CreateImageSection($ObjectPath, $File)
    }
}

<#
.SYNOPSIS
Displays a mapped section in a UI.
.DESCRIPTION
This cmdlet displays a section object inside a UI from where the data can be inspected or edited.
.PARAMETER Section
Specify a section object.
.PARAMETER Wait
Optionally wait for the user to close the UI.
.PARAMETER ReadOnly
Optionally force the viewer to be read-only when passing a section with Map Write access.
.PARAMETER Path
Path to a file to view as a section.
.PARAMETER ObjPath
Path to a object name to view as a section.
.OUTPUTS
None
.EXAMPLE
Show-NtSection $section
Show the mapped section.
.EXAMPLE
Show-NtSection $section -ReadOnly
Show the mapped section as read only.
.EXAMPLE
Show-NtSection $section -Wait
Show the mapped section and wait for the viewer to exit.
.EXAMPLE
Show-NtSection ([byte[]]@(0, 1, 2, 3))
Show an arbitrary byte array in the viewer.
.EXAMPLE
Show-NtSection path\to\file.bin
Show an arbitrary file in the viewer.
#>
function Show-NtSection {
    [CmdletBinding(DefaultParameterSetName = "FromSection")]
    Param(
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "FromSection")]
        [NtCoreLib.NtSection]$Section,
        [Parameter(ParameterSetName = "FromSection")]
        [switch]$ReadOnly,
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "FromData")]
        [byte[]]$Data,
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "FromFile")]
        [string]$Path,
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "FromPath")]
        [string]$ObjPath,
        [switch]$Wait
    )
    switch ($PSCmdlet.ParameterSetName) {
        "FromSection" {
            if (!$Section.IsAccessGranted("MapRead")) {
                Write-Error "Section doesn't have Map Read access."
                return
            }
            Use-NtObject($obj = $Section.Duplicate()) {
                $cmdline = [string]::Format("EditSection --handle {0}", $obj.Handle.DangerousGetHandle())
                if ($ReadOnly) {
                    $cmdline += " --readonly"
                }
                [NtObjectManager.Utils.PSUtils]::StartUtilityProcess("$PSScriptRoot\EditSection.exe", $cmdline, $Wait, $obj)
            }
        }
        "FromData" {
            if ($Data.Length -eq 0) {
                return
            }
            $tempfile = New-TemporaryFile
            $path = $tempfile.FullName
            [System.IO.File]::WriteAllBytes($path, $Data)

            [NtObjectManager.Utils.PSUtils]::StartUtilityProcess("$PSScriptRoot\EditSection.exe", "EditSection --delete --file=""$path""", $Wait)
        }
        "FromFile" {
            $Path = Resolve-Path $Path
            if ($Path -ne "") {
                [NtObjectManager.Utils.PSUtils]::StartUtilityProcess("$PSScriptRoot\EditSection.exe", "EditSection --file=""$Path""", $Wait)
            }
        }
        "FromPath" {
            [NtObjectManager.Utils.PSUtils]::StartUtilityProcess("$PSScriptRoot\EditSection.exe", "EditSection --path=""$ObjPath""", $Wait)
        }
    }
}

<#
.SYNOPSIS
Get a mapped view of a section.
.DESCRIPTION
This cmdlet calls the Map method on a section to map it into memory.
.PARAMETER Section
The section object to map.
.PARAMETER Protection
The protection of the mapping.
.PARAMETER Process
Optional process to map the section into. Default is the current process.
.PARAMETER ViewSize
The size of the view to map, 0 means map the entire section.
.PARAMETER BaseAddress
Base address for the mapping, 0 means pick a location.
.PARAMETER ZeroBits
The number of zero bits in the mapping address.
.PARAMETER CommitSize
The size of memory to commit from the section.
.PARAMETER SectionOffset
Offset into the section for the base address.
.PARAMETER SectionInherit
Inheritance flags for the section.
.PARAMETER AllocationType
The allocation type for the mapping.
.OUTPUTS
NtCoreLib.NtMappedSection - The mapped section.
.EXAMPLE
Add-NtSection -Section $sect -Protection ReadWrite
Map the section as Read/Write.
.EXAMPLE
Add-NtSection -Section $sect -Protection ReadWrite -ViewSize 4096
Map the first 4096 bytes of the section as Read/Write.
.EXAMPLE
Add-NtSection -Section $sect -Protection ReadWrite -SectionOffset (64*1024)
Map the section starting from offset 64k.
#>
function Add-NtSection {
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtSection]$Section,
        [parameter(Mandatory, Position = 1)]
        [NtCoreLib.MemoryAllocationProtect]$Protection,
        [NtCoreLib.NtProcess]$Process,
        [IntPtr]$ViewSize = 0,
        [IntPtr]$BaseAddress = 0,
        [IntPtr]$ZeroBits = 0,
        [IntPtr]$CommitSize = 0,
        [NtCoreLib.LargeInteger]$SectionOffset,
        [NtCoreLib.SectionInherit]$SectionInherit = [NtCoreLib.SectionInherit]::ViewUnmap,
        [NtCoreLib.AllocationType]$AllocationType = "None"
    )

    if ($null -eq $Process) {
        $Process = Get-NtProcess -Current
    }

    $Section.Map($Process, $Protection, $ViewSize, $BaseAddress, `
            $ZeroBits, $CommitSize, $SectionOffset, `
            $SectionInherit, $AllocationType) | Write-Output
}

<#
.SYNOPSIS
Unmap a view of a section.
.DESCRIPTION
This cmdlet unmaps a section from virtual memory.
.PARAMETER Mapping
The mapping to unmap.
.PARAMETER Address
The address to unmap.
.PARAMETER Process
Optional process to unmap from. Default is the current process.
.PARAMETER Flags
Optional flags for unmapping.
.OUTPUTS
None
.EXAMPLE
Remove-NtSection -Mapping $map
Unmap an existing section created with Add-NtSection.
.EXAMPLE
Remove-NtSection -Address $addr
Unmap an address
.EXAMPLE
Remove-NtSection -Address $addr -Process $p
Unmap an address in a specified process.
#>
function Remove-NtSection {
    [CmdletBinding(DefaultParameterSetName = "FromMapping")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromMapping")]
        [NtCoreLib.NtMappedSection]$Mapping,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromAddress")]
        [int64]$Address,
        [parameter(Position = 1, ParameterSetName = "FromAddress")]
        [NtCoreLib.NtProcess]$Process,
        [parameter(ParameterSetName = "FromAddress")]
        [NtCoreLib.MemUnmapFlags]$Flags = 0
    )

    switch ($PsCmdlet.ParameterSetName) {
        "FromMapping" { $Mapping.Dispose() }
        "FromAddress" {
            if ($null -eq $Process) {
                $Process = Get-NtProcess -Current
            }

            $Process.Unmap($Address, $Flags)
        }
    }
}

<#
.SYNOPSIS
Get the cached signing level for a file.
.DESCRIPTION
This cmdlet gets the cached signing level for a specified file.
.PARAMETER Path
The file to get the cached signing level from.
.PARAMETER Win32Path
Specify to treat Path as a Win32 path.
.PARAMETER FromEa
Specify whether to the read the cached signing level from the extended attribute.
.OUTPUTS
NtCoreLib.Security.CodeIntegrity.CachedSigningLevel
.EXAMPLE
Get-NtCachedSigningLevel \??\c:\path\to\file.dll
Get the cached signing level from \??\c:\path\to\file.dll
.EXAMPLE
Get-NtCachedSigningLevel c:\path\to\file.dll -Win32Path
Get the cached signing level from c:\path\to\file.dll converting from a win32 path.
.EXAMPLE
Get-NtCachedSigningLevel \??\c:\path\to\file.dll -FromEa
Get the cached signing level from \??\c:\path\to\file.dll using the extended attribute.
#>
function Get-NtCachedSigningLevel {
    Param(
        [parameter(Position = 0, Mandatory)]
        [string]$Path,
        [switch]$Win32Path,
        [switch]$FromEa
    )

    $access = if ($FromEa) {
        [NtCoreLib.FileAccessRights]::ReadEa
    }
    else {
        [NtCoreLib.FileAccessRights]::ReadData
    }

    Use-NtObject($f = Get-NtFile $Path -Win32Path:$Win32Path -Access $access -ShareMode Read) {
        if ($FromEa) {
            $f.GetCachedSigningLevelFromEa();
        }
        else {
            $f.GetCachedSigningLevel()
        }
    }
}

<#
.SYNOPSIS
Set the cached signing level for a file.
.DESCRIPTION
This cmdlet sets the cached signing level for a specified file.
.PARAMETER Path
The file to set the cached signing level on.
.PARAMETER Win32Path
Specify to treat Path as a Win32 path.
.PARAMETER Flags
Specify the flags for the cache operation.
.PARAMETER SigningLevel
Specify the signing level for the cache operation.
.PARAMETER AdditionalFiles
Specify the additional files for the cache operation.
.PARAMETER CatalogPath
Specify the catalog path for the cache operation.
.PARAMETER PassThru
Specify to return the cached signing level.
INPUTS
None
.OUTPUTS
NtCoreLib.Security.CodeIntegrity.CachedSigningLevel
.EXAMPLE
Set-NtCachedSigningLevel \??\c:\path\to\file.dll
Set the cached signing level to \??\c:\path\to\file.dll
.EXAMPLE
Set-NtCachedSigningLevel c:\path\to\file.dll -Win32Path
Set the cached signing level to \??\c:\path\to\file.dll
#>
function Set-NtCachedSigningLevel {
    Param(
        [parameter(Position = 0, Mandatory)]
        [string]$Path,
        [switch]$Win32Path,
        [int]$Flags = 4,
        [NtCoreLib.Security.CodeIntegrity.SigningLevel]$SigningLevel = 0,
        [NtCoreLib.NtFile[]]$AdditionalFiles,
        [string]$CatalogPath,
        [switch]$PassThru
    )

    Use-NtObject($f = Get-NtFile $Path -Win32Path:$Win32Path -Access ReadData -ShareMode Read, Delete) {
        $f.SetCachedSigningLevel($Flags, $SigningLevel, $AdditionalFiles, $CatalogPath)
        if ($PassThru) {
            $f.GetCachedSigningLevel()
        }
    }
}

<#
.SYNOPSIS
Gets the signing level for an image file.
.DESCRIPTION
This cmdlet gets the signing level for an image file.
.PARAMETER Path
Specify the path to the image file.
.PARAMETER Win32Path
Specify that the path is a Win32 path.
.PARAMETER DontResolve
Specify to not try and resolve the signing level.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.CodeIntegrity.SigningLevel
#>
function Get-NtSigningLevel {
    [CmdletBinding(DefaultParameterSetName="FromPath")]
    param(
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromPath")]
        [string]$Path,
        [Parameter(ParameterSetName="FromPath")]
        [switch]$Win32Path,
        [switch]$DontResolve
    )

    try {
        if ($Win32Path) {
            $Path = Get-NtFilePath -Path $Path
        }

        Use-NtObject($sect = New-NtSectionImage -Path $Path) {
            Use-NtObject($map = $sect.MapRead()) {
                if ($map.ImageSigningLevel -ne "Unchecked" -or $DontResolve) {
                    return $map.ImageSigningLevel
                }

                $script = { 
                    Set-NtProcessMitigationPolicy -Signature AuditMicrosoftSignedOnly
                    [NtObjectManager.Utils.PSUtils]::GetSigningLevel($input) | Out-Null
                }

                $job = Start-Job -ScriptBlock $script -InputObject $Path
                Wait-Job $job | Out-Null

                return $map.ImageSigningLevel
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Compares two signing levels to see which is higher.
.DESCRIPTION
This cmdlet compares two signing levels to see which is higher.
.PARAMETER
.INPUTS
None
.OUTPUTS
Bool
.EXAMPLE
Compare-NtSigningLevel -Left Windows -Right WindowsTCB
Compare two signing levels, returns True if the left level is greater or equal to right.
#>
function Compare-NtSigningLevel {
    param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Security.CodeIntegrity.SigningLevel]$Left,
        [parameter(Mandatory, Position = 1)]
        [NtCoreLib.Security.CodeIntegrity.SigningLevel]$Right
    )
    [NtCoreLib.Security.NtSecurity]::CompareSigningLevel($Left, $Right)
}
