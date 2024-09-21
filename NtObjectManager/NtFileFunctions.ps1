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
Get the NT path for a dos path.
.DESCRIPTION
This cmdlet gets the full NT path for a specified DOS path.
.PARAMETER FullName
The DOS path to convert to NT.
.PARAMETER Resolve
Resolve relative paths to the current PS directory.
.PARAMETER DeviceGuid
Get native path from a Device Interface GUID.
.INPUTS
string[] List of paths to convert.
.OUTPUTS
string Converted path
.EXAMPLE
Get-NtFilePath c:\Windows
Get c:\windows as an NT file path.
.EXAMPLE
Get-ChildItem c:\windows | Get-NtFilePath
Get list of NT file paths from the pipeline.
#>
function Get-NtFilePath {
    [CmdletBinding(DefaultParameterSetName="FromPath")]
    Param(
        [alias("Path")]
        [parameter(Mandatory = $true, Position = 0, ValueFromPipeline, valueFromPipelineByPropertyName, ParameterSetName="FromPath")]
        [string]$FullName,
        [parameter(ParameterSetName="FromPath")]
        [switch]$Resolve,
        [parameter(Mandatory = $true, ParameterSetName="FromGuid")]
        [guid[]]$DeviceGuid
    )

    PROCESS {
        if ($PSCmdlet.ParameterSetName -eq "FromPath") {
            $type = [NtCoreLib.NtFileUtils]::GetDosPathType($FullName)
            $p = $FullName
            if ($Resolve) {
                if ($type -eq "Relative" -or $type -eq "Rooted") {
                    $p = Resolve-Path -LiteralPath $FullName
                }
            }
            try {
                $p = [NtObjectManager.Utils.PSUtils]::ResolveWin32Path($PSCmdlet.SessionState, $p)
                Write-Output $p
            } catch {
                Write-Error $_
            }
        } elseif ($PSCmdlet.ParameterSetName -eq "FromGuid") {
            foreach($g in $DeviceGuid) {
                [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceInterfaceList($g) | Get-NtFilePath | Write-Output
            }
        }
    }
}

<#
.SYNOPSIS
Get the NT path type for a dos path.
.DESCRIPTION
This cmdlet gets the NT path type for a specified DOS path.
.PARAMETER FullName
The DOS path to convert to NT.
.INPUTS
string[] List of paths to convert.
.OUTPUTS
NtCoreLib.RtlPathType
.EXAMPLE
Get-NtFilePathType c:\Windows
Get the path type for c:\windows.
#>
function Get-NtFilePathType {
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$FullName
    )

    [NtCoreLib.NtFileUtils]::GetDosPathType($FullName)
}

<#
.SYNOPSIS
Create a new EA buffer object for use with files.
.DESCRIPTION
This cmdlet creates a new extended attributes buffer object to set on file objects with the SetEa method or with New-NtFile.
.PARAMETER Entries
Optional Hashtable containing entries to initialize into the EA buffer.
.PARAMETER $ExistingBuffer
An existing buffer to initialize the new buffer from.
.INPUTS
None
.OUTPUTS
NtCoreLib.Kernel.IO.EaBuffer
.EXAMPLE
New-NtEaBuffer
Create a new empty EaBuffer object
.EXAMPLE
New-NtEaBuffer @{ INTENTRY = 1234; STRENTRY = "ABC"; BYTEENTRY = [byte[]]@(1,2,3) }
Create a new EaBuffer object initialized with three separate entries.
#>
function New-NtEaBuffer {
    [CmdletBinding(DefaultParameterSetName = "FromEntries")]
    Param(
        [Parameter(ParameterSetName = "FromEntries", Position = 0)]
        [Hashtable]$Entries = @{ },
        [Parameter(ParameterSetName = "FromExisting", Position = 0)]
        [NtCoreLib.Kernel.IO.EaBuffer]$ExistingBuffer
    )

    if ($null -eq $ExistingBuffer) {
        $ea_buffer = New-Object NtCoreLib.Kernel.IO.EaBuffer
        foreach ($entry in $Entries.Keys) {
            $ea_buffer.AddEntry($entry, $Entries.Item($entry), 0)
        }
        return $ea_buffer
    }
    else {
        return New-Object NtCoreLib.Kernel.IO.EaBuffer -ArgumentList $ExistingBuffer
    }
}

<#
.SYNOPSIS
Add an entry to an existing EA buffer.
.DESCRIPTION
This cmdlet adds a new extended attributes entry to a buffer.
.PARAMETER Buffer
The EA buffer to add to.
.PARAMETER Byte
The bytes to add.
.PARAMETER Byte
The bytes to add.
.PARAMETER Byte
The bytes to add.
.PARAMETER Byte
The bytes to add.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Add-NtEaBuffer -Buffer $ea -Name "ABC" -Byte @(0, 1, 2, 3)
Add an entry with name ABC and a set of bytes.
.EXAMPLE
Add-NtEaBuffer -Buffer $ea -Name "ABC" -String "Hello"
Add an entry with name ABC and a string.
.EXAMPLE
Add-NtEaBuffer -Buffer $ea -Name "ABC" -Int 1234
Add an entry with name ABC and an integer.
#>
function Add-NtEaBuffer {
    [CmdletBinding(DefaultParameterSetName="FromString")]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Kernel.IO.EaBuffer]$EaBuffer,
        [Parameter(Mandatory, Position = 1)]
        [string]$Name,
        [Parameter(Mandatory, Position = 2, ParameterSetName="FromString")]
        [string]$String,
        [Parameter(Mandatory, Position = 2, ParameterSetName="FromBytes")]
        [byte[]]$Byte,
        [Parameter(Mandatory, ParameterSetName="FromInt")]
        [int]$Int,
        [NtCoreLib.Kernel.IO.EaBufferEntryFlags]$Flags = 0
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromString" {
            $EaBuffer.AddEntry($Name, $String, $Flags)
        }
        "FromBytes" {
            $EaBuffer.AddEntry($Name, $Byte, $Flags)
        }
        "FromInt" {
            $EaBuffer.AddEntry($Name, $Int, $Flags)
        }
    }
}

<#
.SYNOPSIS
Starts a file oplock with a specific level.
.DESCRIPTION
This cmdlet starts a file oplock with a specific level.
.PARAMETER File
The file to oplock on.
.PARAMETER Level
The oplock level to start.
.PARAMETER LeaseLevel
The oplock lease level to start.
.PARAMETER Flags
Flags for the oplock lease.
.PARAMETER Async
Specify to return an asynchronous task which can be waited on with Wait-AsyncTaskResult.
.INPUTS
None
.OUTPUTS
None or NtCoreLib.RequestOplockOutputBuffer if using LeaseLevel. If Async then a Task.
.EXAMPLE
Start-NtFileOplock $file -Exclusive
Start an exclusive oplock.
.EXAMPLE
Start-NtFileOplock $file -Level Level1
Start a level 1 oplock.
.EXAMPLE
Start-NtFileOplock $file -LeaseLevel Read,Handle
Start a "lease" oplock with Read and Handle levels.
#>
function Start-NtFileOplock {
    [CmdletBinding(DefaultParameterSetName = "OplockLevel")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtFile]$File,
        [parameter(Mandatory, ParameterSetName = "OplockExclusive")]
        [switch]$Exclusive,
        [parameter(Mandatory, Position = 1, ParameterSetName = "OplockLevel")]
        [NtCoreLib.OplockRequestLevel]$Level,
        [parameter(Mandatory, ParameterSetName = "OplockLease")]
        [NtCoreLib.OplockLevelCache]$LeaseLevel,
        [parameter(ParameterSetName = "OplockLease")]
        [NtCoreLib.RequestOplockInputFlag]$Flags = "Request",
        [switch]$Async
    )

    $result = switch ($PSCmdlet.ParameterSetName) {
        "OplockExclusive" {
            if ($Async) {
                $File.OplockExclusiveAsync()
            } else {
                $File.OplockExclusive()
            }
        }
        "OplockLevel" {
            if ($Async) {
                $File.RequestOplockAsync($Level)
            } else {
                $File.RequestOplock($Level)
            }
        }
        "OplockLease" {
            if ($Async) {
                $File.RequestOplockLeaseAsync($LeaseLevel, $Flags)
            } else {
                $File.RequestOplockLease($LeaseLevel, $Flags)
            }
        }
    }

    $result | Write-Output
}

<#
.SYNOPSIS
Acknowledges a file oplock break.
.DESCRIPTION
This cmdlet acknowledges a file oplock break with a specific level.
.PARAMETER File
The file to acknowledge the break on.
.PARAMETER Level
The oplock acknowledge level.
.PARAMETER Lease
Acknowledge a lease oplock and reduce level to None.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Confirm-NtFileOplock $file -Level Acknowledge
Acknowledge an oplock break.
.EXAMPLE
Confirm-NtFileOplock $file -LeaseLevel Read
Acknowledge to a read oplock.
#>
function Confirm-NtFileOplock {
    [CmdletBinding(DefaultParameterSetName = "OplockLevel")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtFile]$File,
        [parameter(Mandatory, Position = 1, ParameterSetName = "OplockLevel")]
        [NtCoreLib.OplockAcknowledgeLevel]$Level,
        [parameter(Mandatory, Position = 1, ParameterSetName = "OplockLease")]
        [switch]$Lease,
        [parameter(ParameterSetName = "OplockLease")]
        [switch]$CompleteOnClose
    )

    switch ($PSCmdlet.ParameterSetName) {
        "OplockLevel" {
            $File.AcknowledgeOplock($Level)
        }
        "OplockLease" {
            $File.AcknowledgeOplockLease($CompleteOnClose)
        }
    }
}

<#
.SYNOPSIS
Get the EA buffer from a file.
.DESCRIPTION
This cmdlet queries for the Extended Attribute buffer from a file by path or from a NtFile object.
.PARAMETER Path
NT path to file.
.PARAMETER Win32Path
Specify Path is a Win32 path.
.PARAMETER File
Specify an existing NtFile object.
.INPUTS
None
.OUTPUTS
NtCoreLib.Kernel.IO.EaBuffer
#>
function Get-NtFileEa {
    [CmdletBinding(DefaultParameterSetName = "FromPath")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromPath")]
        [string]$Path,
        [Parameter(ParameterSetName = "FromPath")]
        [switch]$Win32Path,
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromFile")]
        [NtCoreLib.NtFile]$File,
        [switch]$AsEntries
    )

    $ea = switch ($PsCmdlet.ParameterSetName) {
        "FromFile" {
            $File.GetEa()
        }
        "FromPath" {
            Use-NtObject($f = Get-NtFile -Path $Path -Win32Path:$Win32Path -Access ReadEa) {
                $f.GetEa()
            }
        }
    }
    if ($AsEntries) {
        $ea.Entries | Write-Output
    } else {
        $ea | Write-Output
    }
}

<#
.SYNOPSIS
Set the EA buffer on a file.
.DESCRIPTION
This cmdlet sets the Extended Attribute buffer on a file by path or a NtFile object.
.PARAMETER Path
NT path to file.
.PARAMETER Win32Path
Specify Path is a Win32 path.
.PARAMETER File
Specify an existing NtFile object.
.PARAMETER EaBuffer
Specify the EA buffer to set.
.INPUTS
None
.OUTPUTS
None
#>
function Set-NtFileEa {
    [CmdletBinding(DefaultParameterSetName = "FromPath")]
    Param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromPath")]
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromPathAndName")]
        [string]$Path,
        [Parameter(ParameterSetName = "FromPath")]
        [Parameter(ParameterSetName = "FromPathAndName")]
        [switch]$Win32Path,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromFile")]
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromFileAndName")]
        [NtCoreLib.NtFile]$File,
        [Parameter(Mandatory, Position = 1, ParameterSetName = "FromFile")]
        [Parameter(Mandatory, Position = 1, ParameterSetName = "FromPath")]
        [NtCoreLib.Kernel.IO.EaBuffer]$EaBuffer,
        [Parameter(Mandatory, Position = 1, ParameterSetName = "FromPathAndName")]
        [Parameter(Mandatory, Position = 1, ParameterSetName = "FromFileAndName")]
        [string]$Name,
        [Parameter(Mandatory, Position = 2, ParameterSetName = "FromPathAndName")]
        [Parameter(Mandatory, Position = 2, ParameterSetName = "FromFileAndName")]
        [byte[]]$Byte,
        [Parameter(Position = 3, ParameterSetName = "FromPathAndName")]
        [Parameter(Position = 3, ParameterSetName = "FromFileAndName")]
        [NtCoreLib.Kernel.IO.EaBufferEntryFlags]$Flags = 0
    )

    if ($PSCmdlet.ParameterSetName -eq "FromPathAndName" -or $PSCmdlet.ParameterSetName -eq "FromFileAndName") {
        $EaBuffer = New-NtEaBuffer
        Add-NtEaBuffer -EaBuffer $EaBuffer -Name $Name -Byte $Byte -Flags $Flags
    }

    if ($PSCmdlet.ParameterSetName -eq "FromPath" -or $PSCmdlet.ParameterSetName -eq "FromPathAndName") {
        Use-NtObject($f = Get-NtFile -Path $Path -Win32Path:$Win32Path -Access WriteEa) {
            $f.SetEa($EaBuffer)
        }
    } elseif ($PSCmdlet.ParameterSetName -eq "FromFile" -or $PSCmdlet.ParameterSetName -eq "FromFileAndName"){
        $File.SetEa($EaBuffer)
    }
}

<#
.SYNOPSIS
Remove an EA buffer on a file.
.DESCRIPTION
This cmdlet removes an Extended Attribute buffer on a file by path or a NtFile object.
.PARAMETER Path
NT path to file.
.PARAMETER Win32Path
Specify Path is a Win32 path.
.PARAMETER Name
Specify the name of the buffer to remove.
.INPUTS
None
.OUTPUTS
None
#>
function Remove-NtFileEa {
    [CmdletBinding(DefaultParameterSetName = "FromPath")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromPath")]
        [string]$Path,
        [Parameter(ParameterSetName = "FromPath")]
        [switch]$Win32Path,
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromFile")]
        [NtCoreLib.NtFile]$File,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Name
    )

    switch ($PsCmdlet.ParameterSetName) {
        "FromFile" {
            $File.RemoveEa($Name)
        }
        "FromPath" {
            Use-NtObject($f = Get-NtFile -Path $Path -Win32Path:$Win32Path -Access WriteEa) {
                $f.RemoveEa($Name)
            }
        }
    }
}

<#
.SYNOPSIS
Write bytes to a file.
.DESCRIPTION
This cmdlet writes bytes to a file optionally specifying the offset.
.PARAMETER File
Specify the file to write to.
.PARAMETER Bytes
Specify the bytes to write.
.PARAMETER Offset
Specify the offset in the file to write to.
.PARAMETER PassThru
Specify to the return the length written.
.INPUTS
None
.OUTPUTS
int
.EXAMPLE
Write-NtFile -File $f -Bytes @(0, 1, 2, 3)
Write to a file at the current offset.
.EXAMPLE
Write-NtFile -File $f -Bytes @(0, 1, 2, 3) -Offset 1234
Write to a file at offset 1234.
.EXAMPLE
$count = Write-NtFile -File $f -Bytes @(0, 1, 2, 3) -PassThru
Write to a file and return the number of bytes written.
#>
function Write-NtFile {
    [CmdletBinding(DefaultParameterSetName = "NoOffset")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtFile]$File,
        [parameter(Mandatory, Position = 1)]
        [byte[]]$Bytes,
        [parameter(Position = 2, ParameterSetName="UseOffset")]
        [int64]$Offset,
        [switch]$PassThru
    )
    $result = switch($PSCmdlet.ParameterSetName) {
        "NoOffset" {
            $File.Write($Bytes)
        }
        "UseOffset" {
            $File.Write($Bytes, $Offset)
        }
    }

    if ($PassThru) {
        $result | Write-Output
    }
}

<#
.SYNOPSIS
Read bytes from a file.
.DESCRIPTION
This cmdlet writes byte to a file optionally specifying the offset.
.PARAMETER File
Specify the file to read from.
.PARAMETER Length
Specify the number of bytes to read.
.PARAMETER Offset
Specify the offset in the file to read from.
.INPUTS
None
.OUTPUTS
byte[]
.EXAMPLE
Read-NtFile -File $f -Length 8
Read 8 bytes from a file at the current offset.
.EXAMPLE
Read-NtFile -File $f -Length 8 -Offset 1234
Read 8 bytes from a file at offset 1234.
#>
function Read-NtFile {
    [CmdletBinding(DefaultParameterSetName = "NoOffset")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtFile]$File,
        [parameter(Mandatory, Position = 1)]
        [int]$Length,
        [parameter(Position = 2, ParameterSetName="UseOffset")]
        [int64]$Offset
    )

    $result = switch($PSCmdlet.ParameterSetName) {
        "NoOffset" {
            $File.Read($Length)
        }
        "UseOffset" {
            $File.Read($Length, $Offset)
        }
    }

    Write-Output $result 
}

<#
.SYNOPSIS
Enumerate file entries for a file directory.
.DESCRIPTION
This cmdlet enumerates directory entries from a file directory.
.PARAMETER File
Specify the file directory to enumerate.
.PARAMETER Pattern
A file pattern to specify the files to enumerate. e.g. *.txt.
.PARAMETER FileType
Specify all files or either files or directories.
.PARAMETER ReparsePoint
Enumerate reparse point information.
.PARAMETER ObjectId
Enumerate object ID information.
.PARAMETER IncludePlaceholder
Include placeholder directories in output.
.PARAMETER FileId
Include file ID in the entries.
.PARAMETER ShortName
Include the short name in the output.
.PARAMETER Path
Path to open the directory first.
.PARAMETER Win32Path
Open a win32 path.
.PARAMETER CaseSensitive
Open the file case sensitively, also does case sensitive pattern matching.
.INPUTS
None
.OUTPUTS
NtCoreLib.Kernel.IO.FileDirectoryEntry[]
NtCoreLib.Kernel.IO.FileIdDirectoryEntry[]
NtCoreLib.Kernel.IO.NtFileReparsePoint[]
NtCoreLib.Kernel.IO.NtFileObjectId[]
.EXAMPLE
Get-NtFileItem -File $f
Enumerate all file items.
.EXAMPLE
Get-NtFileItem -Path \??\c:\windows
Enumerate all file items in c:\windows.
.EXAMPLE
Get-NtFileItem -Path c:\windows -Win32Path
Enumerate all file items in c:\windows.
.EXAMPLE
Get-NtFileItem -File $f -Pattern *.txt
Enumerate all files with a TXT extension.
.EXAMPLE
Get-NtFileItem -File $f -FileType FilesOnly
Enumerate only files.
.EXAMPLE
Get-NtFileItem -File $f -FileType DirectoriesOnly
Enumerate only directories.
.EXAMPLE
Get-NtFileItem -File $f -ReparsePoint
Enumerate reparse points.
.EXAMPLE
Get-NtFileItem -File $f -ObjectId
Enumerate object IDs.
.EXAMPLE
Get-NtFileItem -File $f -FileId
Enumerate files with file ID.
.EXAMPLE
Get-NtFileItem -File $f -ShortName
Enumerate files with short name.
#>
function Get-NtFileItem {
    [CmdletBinding(DefaultParameterSetName = "Default")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName="Default")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromReparsePoint")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromObjectID")]
        [NtCoreLib.NtFile]$File,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromPath")]
        [string]$Path,
        [parameter(ParameterSetName="FromPath")]
        [switch]$Win32Path,
        [parameter(ParameterSetName="Default")]
        [parameter(ParameterSetName="FromPath")]
        [string]$Pattern = "*",
        [parameter(ParameterSetName="Default")]
        [parameter(ParameterSetName="FromPath")]
        [NtCoreLib.FileTypeMask]$FileType = "All",
        [parameter(ParameterSetName="Default")]
        [parameter(ParameterSetName="FromPath")]
        [switch]$FileId,
        [parameter(ParameterSetName="Default")]
        [parameter(ParameterSetName="FromPath")]
        [switch]$ShortName,
        [parameter(ParameterSetName="Default")]
        [parameter(ParameterSetName="FromPath")]
        [switch]$IncludePlaceholder,
        [parameter(ParameterSetName="FromPath")]
        [switch]$CaseSensitive,
        [parameter(ParameterSetName="FromReparsePoint")]
        [switch]$ReparsePoint,
        [parameter(ParameterSetName="FromObjectID")]
        [switch]$ObjectId
    )

    switch($PSCmdlet.ParameterSetName) {
        "Default" {
            $flags = "Default"
            if ($FileId -and $ShortName) {
                $flags = "FileId, ShortName"
            } elseif($FileId) {
                $flags = "FileId"
            } elseif($ShortName) {
                $flags = "ShortName"
            }

            if ($IncludePlaceholder) {
                $flags += ", Placeholders"
            }
            $File.QueryDirectoryInfo($Pattern, $FileType, $flags) | Write-Output
        }
        "FromPath" {
            $attr = "CaseInsensitive"
            if ($CaseSensitive) {
                $attr = 0
            }
            Use-NtObject($file = Get-NtFile -Path $Path -Win32Path:$Win32Path `
                -DirectoryAccess ListDirectory -ShareMode Read -Options DirectoryFile -AttributeFlags $attr) {
                if ($file -ne $null) {
                    Get-NtFileItem -File $file -Pattern $Pattern -FileType $FileType -FileId:$FileId `
                        -ShortName:$ShortName -IncludePlaceholder:$IncludePlaceholder | Write-Output
                }
            }
        }
        "FromReparsePoint" {
            $File.QueryReparsePoints() | Write-Output
        }
        "FromObjectID" {
            $File.QueryObjectIds() | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get change notification events for a file directory.
.DESCRIPTION
This cmdlet gets change notification envents for a file directory.
.PARAMETER File
Specify the file directory to get change notification events from.
.PARAMETER Filter
Specify what types of events to receive.
.PARAMETER WatchSubtree
Specify to watch all directories in a subtree.
.PARAMETER TimeoutSec
Specify a timeout in seconds to wait if the handle is asynchronous.
.PARAMETER Async
Specify to return an asynchronous task instead of waiting. You can use Wait-AsyncTaskResult
to get the result. The handle must be asynchronous.
.INPUTS
None
.OUTPUTS
NtCoreLib.DirectoryChangeNotification[]
.EXAMPLE
Get-NtFileChange -File $f
Get all change notifications for the file directory.
.EXAMPLE
Get-NtFileChange -File $f -Filter FileName
Get only filename change notifications for the file directory.
.EXAMPLE
Get-NtFileChange -File $f -WatchSubtree
Get all change notifications for the file directory and its children.
.EXAMPLE
Get-NtFileChange -File $f -TimeoutSec 10
Get all change notifications for the file directory, waiting for 10 seconds for a result.
#>
function Get-NtFileChange {
    [CmdletBinding(DefaultParameterSetName = "Sync")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtFile]$File,
        [NtCoreLib.DirectoryChangeNotifyFilter]$Filter = "All",
        [switch]$WatchSubtree,
        [parameter(ParameterSetName="Sync")]
        [int]$TimeoutSec = -1,
        [parameter(Mandatory, ParameterSetName="Async")]
        [switch]$Async
    )

    if ($Async) {
        $File.GetChangeNotificationFullAsync($Filter, $WatchSubtree) | Write-Output
    } else {
        $timeout = Get-NtWaitTimeout -Infinite
        if ($TimeoutSec -ge 0) {
            $timeout = Get-NtWaitTimeout -Second $TimeoutSec
        }
        $File.GetChangeNotificationFull($Filter, $WatchSubtree, $timeout) | Write-Output
    }
}

<#
.SYNOPSIS
Lock a file range.
.DESCRIPTION
This cmdlet locks a file range in an open file.
.PARAMETER File
Specify the file directory to lock.
.PARAMETER Offset
The offset into the file to lock.
.PARAMETER Length
The length of the locked region. 
.PARAMETER All
Specify to lock the entire file.
.PARAMETER Wait
Specify to wait for the lock to be available otherwise fail immediately.
.PARAMETER Exclusive
Specify to create an exclusive lock.
.PARAMETER PassThru
Specify to return a scoped lock which will unlock when disposed.
.INPUTS
None
.OUTPUTS
NtCoreLib.Utilities.IO.NtFileScopedLock
.EXAMPLE
Lock-NtFile -File $f -Offset 0 -Length 256
Lock the first 256 bytes.
.EXAMPLE
Lock-NtFile -File $f -Offset 0 -Length 256 -Wait
Lock the first 256 bytes and wait if already locked.
.EXAMPLE
Lock-NtFile -File $f -All
Lock the entire file.
.EXAMPLE
Lock-NtFile -File $f -All -Exclusive
Lock the entire file exclusively.
#>
function Lock-NtFile {
    [CmdletBinding(DefaultParameterSetName = "FromOffset")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtFile]$File,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromOffset")]
        [int64]$Offset,
        [parameter(Mandatory, Position = 2, ParameterSetName="FromOffset")]
        [int64]$Length,
        [parameter(Mandatory, ParameterSetName="All")]
        [switch]$All,
        [switch]$Wait,
        [switch]$Exclusive,
        [switch]$PassThru
    )

    if ($All) {
        $Offset = 0
        $Length = $File.Length
    }

    if ($PassThru) {
        [NtCoreLib.Utilities.IO.NtFileScopedLock]::Create($File, $Offset, $Length, !$Wait, $Exclusive) | Write-Output
    } else {
        $File.Lock($Offset, $Length, !$Wait, $Exclusive)
    }
}

<#
.SYNOPSIS
Unlock a file range.
.DESCRIPTION
This cmdlet unlocks a file range in an open file.
.PARAMETER File
Specify the file directory to unlock.
.PARAMETER Offset
The offset into the file to unlock.
.PARAMETER Length
The length of the unlocked region. 
.PARAMETER All
Specify to unlock the entire file.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Unlock-NtFile -File $f -Offset 0 -Length 256
Unlock the first 256 bytes.
.EXAMPLE
Unlock-NtFile -File $f -All
Unlock the entire file.
#>
function Unlock-NtFile {
    [CmdletBinding(DefaultParameterSetName = "FromOffset")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtFile]$File,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromOffset")]
        [int64]$Offset,
        [parameter(Mandatory, Position = 2, ParameterSetName="FromOffset")]
        [int64]$Length,
        [parameter(Mandatory, ParameterSetName="All")]
        [switch]$All
    )

    if ($All) {
        $Offset = 0
        $Length = $File.Length
    }

    $File.Unlock($Offset, $Length)
}

<#
.SYNOPSIS
Sets the disposition on a file.
.DESCRIPTION
This cmdlet sets the disposition on a file such as deleting the file.
.PARAMETER File
Specify the file to set.
.PARAMETER Delete
Specify to mark the file as delete on close.
.PARAMETER PosixSemantics
Specify to mark the file as delete on close with POSIX semantics.
.PARAMETER Flags
Specify disposition flags.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-NtFileDisposition -File $f -Delete
Set the file to delete on close.
.EXAMPLE
Set-NtFileDisposition -File $f -Delete:$false
Clear the file delete on close flag.
.EXAMPLE
Set-NtFileDisposition -File $f -Delete -PosixSemantics
Set the file to delete on close with POSIX semantics.
.EXAMPLE
Set-NtFileDisposition -File $f -Flags Delete, IgnoreReadOnlyAttribute
Set the file delete on close flag and ignore the readonly attribute.
#>
function Set-NtFileDisposition {
    [CmdletBinding(DefaultParameterSetName="FromDelete")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtFile]$File,
        [parameter(Mandatory, ParameterSetName="FromDelete")]
        [switch]$Delete,
        [parameter(ParameterSetName="FromDelete")]
        [switch]$PosixSemantics,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromFlags")]
        [NtCoreLib.FileDispositionInformationExFlags]$Flags
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromDelete" {
            if ($PosixSemantics -and $Delete) {
                $File.SetDispositionEx("Delete, PosixSemantics")
            } else {
                $File.SetDisposition($Delete)
            }
        }
        "FromFlags" {
            $File.SetDispositionEx($Flags)
        }
    }
}

<#
.SYNOPSIS
Gets whether the file is being deleted.
.DESCRIPTION
This cmdlet gets whether the file is going to be deleted when closed.
.PARAMETER File
Specify the file to query.
.INPUTS
None
.OUTPUTS
bool
.EXAMPLE
Get-NtFileDisposition -File $f
Get the file to delete on close flag.
#>
function Get-NtFileDisposition {
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtFile]$File
    )
    $File.DeletePending | Write-Output
}

<#
.SYNOPSIS
Generate a 8dot3 name for a full name.
.DESCRIPTION
This cmdlet generates a 8dot3 filename from a full name.
.PARAMETER Name
The name to generate from.
.PARAMETER ExtendedCharacters
Allow extended characters.
.INPUTS
None
.OUTPUTS
string
.EXAMPLE
Get-NtFile8dot3Path -Name 0123456789.config 
Generate a 8dot3 name from a full name.
#>
function Get-NtFile8dot3Name {
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [string]$Name,
        [switch]$ExtendedCharacters
    )
    [NtCoreLib.NtFileUtils]::Generate8dot3Name($Name, $ExtendedCharacters) | Write-Output
}

<#
.SYNOPSIS
Tests if a driver is in the device stack of a file.
.DESCRIPTION
This cmdlet checks if a driver is in the device stack of a file.
.PARAMETER File
The file to check. Works with files or direct device opens.
.PARAMETER DriverPath
The object manager path to the driver object. e.g. \Device\volume or just volume.
.INPUTS
None
.OUTPUTS
Bool
.EXAMPLE
Test-NtFileDriverPath -File $f -DriverPath "Ntfs"
Tests if the Ntfs driver is in the path.
#>
function Test-NtFileDriverPath {
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtFile]$File,
        [parameter(Mandatory = $true, Position = 1)]
        [string]$DriverPath
    )
    $File.DriverInPath($DriverPath)
}

<#
.SYNOPSIS
Get list of mount points.
.DESCRIPTION
This cmdlet queries the mount point manager for a list of mount points.
.INPUTS
None
.OUTPUTS
NtCoreLib.IO.MountPointManager.MountPoint[]
.EXAMPLE
Get-NtMountPoint
Get list of mount points.
#>
function Get-NtMountPoint {
    [NtCoreLib.IO.MountPointManager.MountPointManagerUtils]::QueryMountPoints() | Write-Output
}

<#
.SYNOPSIS
Create a new reparse tag buffer.
.DESCRIPTION
This cmdlet creates a new reparse tag buffer.
.PARAMETER Tag
Specify the reparse tag.
.PARAMETER Guid
Specify the GUID for a generic reparse buffer.
.PARAMETER Data
Specify data for the reparse buffer.
.INPUTS
None
.OUTPUTS
NtCoreLib.Kernel.IO.OpaqueReparseBuffer
NtCoreLib.Kernel.IO.GenericReparseBuffer
.EXAMPLE
New-NtFileReparseBuffer -Tag AF_UNIX -Data @(1, 2, 3, 4)
Create a new opaque reparse buffer.
.EXAMPLE
New-NtFileReparseBuffer -GenericTag 100 -Data @(1, 2, 3, 4) -Guid '8b049aa1-e380-4808-aeb4-dffd9d01c0de'
Create a new opaque reparse buffer.
#>
function New-NtFileReparseBuffer {
    [CmdletBinding(DefaultParameterSetName = "OpaqueBuffer")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName="OpaqueBuffer")]
        [NtCoreLib.Kernel.IO.ReparseTag]$Tag,
        [parameter(Mandatory, Position = 0, ParameterSetName="GenericBuffer")]
        [uint32]$GenericTag,
        [parameter(Mandatory, ParameterSetName="GenericBuffer")]
        [guid]$Guid,
        [parameter(Mandatory, Position = 1, ParameterSetName="OpaqueBuffer")]
        [parameter(Mandatory, Position = 1, ParameterSetName="GenericBuffer")]
        [AllowEmptyCollection()]
        [byte[]]$Data
    )

    switch($PSCmdlet.ParameterSetName) {
        "OpaqueBuffer" {
            [NtCoreLib.Kernel.IO.OpaqueReparseBuffer]::new($Tag, $Data) | Write-Output
        }
        "GenericBuffer" {
            [NtCoreLib.Kernel.IO.GenericReparseBuffer]::new($GenericTag, $Guid, $Data) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Query the quota on a volume.
.DESCRIPTION
This cmdlet queries the quote entries on a volume.
.PARAMETER Volume
Specify the name of the volume, e.g. C: or \Device\HarddiskVolumeX
.PARAMETER Sid
Specify a list of sids to query.
.INPUTS
None
.OUTPUTS
NtCoreLib.Kernel.IO.FileQuotaEntry[]
.EXAMPLE
Get-NtFileQuota -Volume C:
Query the quota for the C: volume.
#>
function Get-NtFileQuota {
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$Volume,
        [NtCoreLib.Security.Authorization.Sid[]]$Sid
    )
    try {
        if (!$Volume.StartsWith("\")) {
            $Volume = "\??\" + $Volume
        }
        Use-NtObject($vol = Get-NtFile -Path $Volume `
            -Access Execute -Share Read, Write) {
            $vol.QueryQuota($Sid) | Write-Output
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Sets the quota on a volume.
.DESCRIPTION
This cmdlet sets the quote entries on a volume.
.PARAMETER Volume
Specify the name of the volume, e.g. C: or \Device\HarddiskVolumeX
.PARAMETER Sid
Specify the SID to set.
.PARAMETER Limit
Specify the quota limit.
.PARAMETER Threshold
Specify the quota threshold.
.PARAMETER Quota
Specify a list of quota entries.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-NtFileQuota -Volume C: -Sid "S-1-1-0" -Limit (10*1024*1024) -Threshold (8*1024*1024)
Set quota for the Everyone group with a limit of 10MiB and threshold of 8MiB.
.EXAMPLE
Set-NtFileQuota -Volume C: -Quota $qs
Set quota for a list of quota entries.
#>
function Set-NtFileQuota {
    [CmdletBinding(DefaultParameterSetName="FromSid")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$Volume,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromSid")]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [parameter(Mandatory, Position = 2, ParameterSetName="FromSid")]
        [int64]$Limit,
        [parameter(Mandatory, Position = 3, ParameterSetName="FromSid")]
        [int64]$Threshold,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromEntry")]
        [NtCoreLib.Kernel.IO.FileQuotaEntry[]]$Quota
    )
    try {
        if (!$Volume.StartsWith("\")) {
            $Volume = "\??\" + $Volume
        }
        Use-NtObject($vol = Get-NtFile -Path $Volume `
            -Access WriteData -Share Read, Write) {
            if ($PSCmdlet.ParameterSetName -eq "FromSid") {
                $vol.SetQuota($Sid, $Threshold, $Limit)
            } else {
                $vol.SetQuota($Quota)
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Read the USN journal for a volume.
.DESCRIPTION
This cmdlet reads the USN journal reocrds for a volume.
.PARAMETER Volume
Specify the volume to read from.
.PARAMETER StartUsn
Specify the first USN to read from.
.PARAMETER EndUsn
Specify the last USN to read, exclusive.
.PARAMETER ReasonMask
Specify a mask of reason codes to return.
.PARAMETER Unprivileged
Specify to use unprivileged reading. This doesn't return filenames you don't have access to.
.INPUTS
None
.OUTPUTS
NtCoreLib.IO.UsnJournal.UsnJournalRecord[]
.EXAMPLE
Read-NtFileUsnJournal -Volume C:
Read the USN journal for the C: volume.
#>
function Read-NtFileUsnJournal {
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$Volume,
        [uint64]$StartUsn = 0,
        [uint64]$EndUsn = [uint64]::MaxValue,
        [NtCoreLib.IO.UsnJournal.UsnJournalReasonFlags]$ReasonMask = "All",
        [switch]$Unprivileged
    )
    try {
        if (!$Volume.StartsWith("\")) {
            $Volume = "\??\" + $Volume
        }

        $Access = "ReadData"

        if ($Unprivileged) {
            $Volume += "\"
            $Access = "Synchronize"
        }

        Use-NtObject($vol = Get-NtFile -Path $Volume `
            -Access $Access -Share Read, Write) {
            if ($Unprivileged) {
                [NtCoreLib.IO.UsnJournal.UsnJournalUtils]::ReadJournalUnprivileged($vol, $StartUsn, $EndUsn, $ReasonMask) | Write-Output
            } else {
                [NtCoreLib.IO.UsnJournal.UsnJournalUtils]::ReadJournal($vol, $StartUsn, $EndUsn, $ReasonMask) | Write-Output
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Gets an IO control code structure.
.DESCRIPTION
This cmdlet gets an IO control code structure from a code or from its constituent parts.
.PARAMETER ControlCode
Specify the control code for the structure.
.PARAMETER DeviceType
Specify the device type component.
.PARAMETER Function
Specify the function code component.
.PARAMETER Method
Specify the control method component.
.PARAMETER Access
Specify the access component.
.PARAMETER LookupName
Specify to try and lookup a known name for the IO control code. If no name found will just return an empty string.
.PARAMETER All
Specify to return all known IO control codes with names.
.PARAMETER Name
Specify to lookup an IO control code with a name.
.PARAMETER AsInt
When looking up by name return the control code as an integer.
.OUTPUTS
NtCoreLib.NtIoControlCode
System.String
.EXAMPLE
Get-NtIoControlCode 0x110028
Get the IO control code structure for a control code.
.EXAMPLE
Get-NtIoControlCode 0x110028 -LookupName
Get the IO control code structure for a control code and lookup its name (if known).
.EXAMPLE
Get-NtIoControlCode -DeviceType NAMED_PIPE -Function 10 -Method Buffered -Access Any
Get the IO control code structure from component parts.
.EXAMPLE
Get-NtIoControlCode -DeviceType NAMED_PIPE -Function 10 -Method Buffered -Access Any -LookupName
Get the IO control code structure from component parts and lookup its name (if known).
.EXAMPLE
Get-NtIoControlCode -Name "FSCTL_GET_REPARSE_POINT"
Get the IO control code structure from a known name.
.EXAMPLE
Get-NtIoControlCode -Name "FSCTL_GET_REPARSE_POINT" -AsInt
Get the IO control code structure from a known name as output an integer.
#>
function Get-NtIoControlCode {
    [CmdletBinding(DefaultParameterSetName = "FromCode")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromCode", Mandatory = $true)]
        [int]$ControlCode,
        [Parameter(ParameterSetName = "FromParts", Mandatory = $true)]
        [NtCoreLib.FileDeviceType]$DeviceType,
        [Parameter(ParameterSetName = "FromParts", Mandatory = $true)]
        [int]$Function,
        [Parameter(ParameterSetName = "FromParts", Mandatory = $true)]
        [NtCoreLib.FileControlMethod]$Method,
        [Parameter(ParameterSetName = "FromParts", Mandatory = $true)]
        [NtCoreLib.FileControlAccess]$Access,
        [Parameter(ParameterSetName = "FromParts")]
        [Parameter(ParameterSetName = "FromCode")]
        [switch]$LookupName,
        [Parameter(ParameterSetName = "FromAll", Mandatory = $true)]
        [switch]$All,
        [Parameter(ParameterSetName = "FromName", Mandatory = $true)]
        [string]$Name,
        [Parameter(ParameterSetName = "FromParts")]
        [Parameter(ParameterSetName = "FromName")]
        [switch]$AsInt
    )
    $result = switch ($PsCmdlet.ParameterSetName) {
        "FromCode" {
            [NtCoreLib.NtIoControlCode]::new($ControlCode)
        }
        "FromParts" {
            [NtCoreLib.NtIoControlCode]::new($DeviceType, $Function, $Method, $Access)
        }
        "FromAll" {
            [NtCoreLib.NtWellKnownIoControlCodes]::GetKnownControlCodes()
        }
        "FromName" {
            [NtCoreLib.NtWellKnownIoControlCodes]::GetKnownControlCodeByName($Name)
        }
    }

    if ($LookupName) {
        return [NtCoreLib.NtWellKnownIoControlCodes]::KnownControlCodeToName($result)
    }

    if ($AsInt) {
        $result.ToInt32() | Write-Output
    } else {
        $result | Write-Output
    }
}
