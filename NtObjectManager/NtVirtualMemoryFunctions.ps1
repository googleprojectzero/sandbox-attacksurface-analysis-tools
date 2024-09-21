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
Allocates a new block of virtual memory.
.DESCRIPTION
This cmdlet allocates a new block of virtual memory in a specified process with specified set of protection. Returns the address.
.PARAMETER Size
The size of the allocated memory region.
.PARAMETER BaseAddress
Optional address to allocate the memory at. Can be 0 which requests the kernel to pick an address.
.PARAMETER Process
The process to allocate the memory in, defaults to current process.
.PARAMETER AllocationType
The type of allocation to make. Defaults to Reserve and Commit.
.PARAMETER Protection
The protection for the memory region. Defaults to ReadWrite.
.PARAMETER AsBuffer
Specify to return as a safe buffer in the current virtual address space.
.PARAMETER ExtendedParams
Specify extended parameters for the allocation.
.OUTPUTS
int64
NtCoreLib.Native.SafeBuffers.SafeVirtualMemoryBuffer
.EXAMPLE
$addr = Add-NtVirtualMemory 0x10000
Allocate a block 0x10000 in size.
.EXAMPLE
$addr = Add-NtVirtualMemory 0x10000 -Process $process
Allocate a block 0x10000 in size in the specified process.
.EXAMPLE
$addr = Add-NtVirtualMemory 0x10000 -AllocationType Reserve
Reserve a block 0x10000 in size but don't yet commit it.
.EXAMPLE
$addr = Add-NtVirtualMemory 0x10000 -Protection ExecuteReadWrite
Allocate a block 0x10000 in size with Read, Write and Execution protection.
#>
function Add-NtVirtualMemory {
    [CmdletBinding(DefaultParameterSetName="FromProcess")]
    param (
        [parameter(Mandatory, Position = 0)]
        [int64]$Size,
        [int64]$BaseAddress,
        [parameter(ParameterSetName="FromProcess")]
        [NtCoreLib.NtProcess]$Process = [NtCoreLib.NtProcess]::Current,
        [NtCoreLib.MemoryAllocationType]$AllocationType = "Reserve, Commit",
        [NtCoreLib.MemoryAllocationProtect]$Protection = "ReadWrite",
        [parameter(Mandatory, ParameterSetName="AsBuffer")]
        [switch]$AsBuffer,
        [NtCoreLib.Kernel.Memory.MemoryExtendedParameter[]]$ExtendedParams
    )
    if ($AsBuffer) {
        [NtCoreLib.Native.SafeBuffers.SafeVirtualMemoryBuffer]::new($BaseAddress, $Size, $AllocationType, $Protection, $ExtendedParams)
    } else {
        $Process.AllocateMemory($BaseAddress, $Size, $AllocationType, $Protection, $ExtendedParams)
    }
}

<#
.SYNOPSIS
Deallocates a block of virtual memory.
.DESCRIPTION
This cmdlet deallocates a block of virtual memory in a specified process.
.PARAMETER Size
The size of the region to  decommit. Only valid when FreeType is Decommit.
.PARAMETER Address
The address to deallocate the memory at.
.PARAMETER Process
The process to deallocate the memory in, defaults to current process.
.PARAMETER MemoryType
The type of allocation operation to perform. Release frees the memory while
Decommit makes it inaccessible.
.OUTPUTS
None
.EXAMPLE
Remove-NtVirtualMemory $addr
Free block at $addr
.EXAMPLE
Remove-NtVirtualMemory $addr -Process $process
Free a block in the specified process.
.EXAMPLE
Remove-NtVirtualMemory $addr -Size 0x1000 -FreeType Decommit
Decommit a 4096 byte block at $addr
#>
function Remove-NtVirtualMemory {
    param (
        [parameter(Mandatory, Position = 0)]
        [int64]$Address,
        [int64]$Size,
        [NtCoreLib.MemoryFreeType]$FreeType = "Release",
        [NtCoreLib.NtProcess]$Process = [NtCoreLib.NtProcess]::Current
    )
    $Process.FreeMemory($Address, $Size, $FreeType)
}

<#
.SYNOPSIS
Get information about a virtual memory region by address or for the entire process.
.DESCRIPTION
This cmdlet gets information about a virtual memory region or all regions in a process.
.PARAMETER Address
The address to get information about.
.PARAMETER Process
The process to query for memory information, defaults to current process.
.PARAMETER All
Show all memory regions.
.PARAMETER Name
Show only memory regions for the named mapped file.
.PARAMETER IncludeFree
When showing all memory regions specify to include free regions as well.
.OUTPUTS
NtCoreLib.MemoryInformation
.EXAMPLE
Get-NtVirtualMemory $addr
Get the memory information for the specified address for the current process.
.EXAMPLE
Get-NtVirtualMemory $addr -Process $process
Get the memory information for the specified address in another process.
.EXAMPLE
Get-NtVirtualMemory
Get all memory information for the current process.
.EXAMPLE
Get-NtVirtualMemory -Process $process
Get all memory information in another process.
.EXAMPLE
Get-NtVirtualMemory -Process $process -IncludeFree
Get all memory information in another process including free regions.
.EXAMPLE
Get-NtVirtualMemory -Type Mapped
Get all mapped memory information for the current process.
.EXAMPLE
Get-NtVirtualMemory -Name file.exe
Get all mapped memory information where the mapped name is file.exe.
#>
function Get-NtVirtualMemory {
    [CmdletBinding(DefaultParameterSetName = "All")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromAddress")]
        [int64]$Address,
        [NtCoreLib.NtProcess]$Process = [NtCoreLib.NtProcess]::Current,
        [parameter(ParameterSetName = "All")]
        [switch]$All,
        [parameter(ParameterSetName = "All")]
        [switch]$IncludeFree,
        [NtCoreLib.MemoryType]$Type = "All",
        [parameter(ParameterSetName = "All")]
        [NtCoreLib.MemoryState]$State = "Commit, Reserve",
        [parameter(ParameterSetName = "All")]
        [string]$Name
    )
    switch ($PsCmdlet.ParameterSetName) {
        "FromAddress" {
            $Process.QueryMemoryInformation($Address) | Write-Output
        }
        "All" {
            if ($IncludeFree) {
                $State = $State -bor "Free"
            }
            if ($Name -ne "") {
                $Process.QueryAllMemoryInformation($Type, $State) | Where-Object Name -eq $Name | Write-Output
            }
            else {
                $Process.QueryAllMemoryInformation($Type, $State) | Write-Output
            }
        }
    }
}

<#
.SYNOPSIS
Set protection flags for a virtual memory region.
.DESCRIPTION
This cmdlet sets protection flags for a region of virtual memory in the current process or another specified process.
.PARAMETER Address
The address location to set the memory protection.
.PARAMETER Size
The size of the memory region to set.
.PARAMETER Process
The process to set the memory in, defaults to current process.
.PARAMETER Protection
Specify the new protection for the memory region.
.OUTPUTS
NtCoreLib.MemoryAllocationProtect - The previous memory protection setting.
.EXAMPLE
Set-NtVirtualMemory $addr 0x1000 ExecuteRead
Sets the protection of a memory region to ExecuteRead.
#>
function Set-NtVirtualMemory {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position = 0)]
        [int64]$Address,
        [parameter(Mandatory, Position = 1)]
        [int64]$Size,
        [parameter(Mandatory, Position = 2)]
        [NtCoreLib.MemoryAllocationProtect]$Protection,
        [NtCoreLib.NtProcess]$Process = [NtCoreLib.NtProcess]::Current
    )
    $Process.ProtectMemory($Address, $Size, $Protection)
}

<#
.SYNOPSIS
Reads bytes from a virtual memory region.
.DESCRIPTION
This cmdlet reads the bytes from a region of virtual memory in the current process or another specified process.
.PARAMETER Address
The address location to read.
.PARAMETER Size
The size of the memory to read. This is the maximum, if the memory address is invalid the returned buffer can be smaller.
.PARAMETER Process
The process to read from, defaults to current process.
.PARAMETER ReadAll
Specify to ensure you read all the requested memory from the process.
.PARAMETER Mapping
Specify a mapped section object.
.PARAMETER Offset
Specify the offset into the mapped section.
.OUTPUTS
byte[] - The array of read bytes. The size of the output might be smaller than the requested size.
.EXAMPLE
Read-NtVirtualMemory $addr 0x1000
Read up to 4096 from $addr.
.EXAMPLE
Read-NtVirtualMemory $addr 0x1000 -Process $process
Read up to 4096 from $addr in another process.
.EXAMPLE
Read-NtVirtualMemory $addr 0x1000 -ReadAll
Read up to 4096 from $addr, fail if can't read all the bytes.
.EXAMPLE
Read-NtVirtualMemory $map -Offset 100 -Size 512
Read up to 512 bytes from offset 100 into a mapped file.
#>
function Read-NtVirtualMemory {
    [CmdletBinding(DefaultParameterSetName="FromAddress")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName="FromAddress")]
        [int64]$Address,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromMapping")]
        [NtCoreLib.NtMappedSection]$Mapping,
        [parameter(ParameterSetName="FromMapping")]
        [int64]$Offset = 0,
        [parameter(Mandatory, Position = 1)]
        [int]$Size,
        [parameter(ParameterSetName="FromAddress")]
        [NtCoreLib.NtProcess]$Process = [NtCoreLib.NtProcess]::Current,
        [switch]$ReadAll
    )

    if ($PSCmdlet.ParameterSetName -eq "FromMapping") {
        $Address = $Mapping.BaseAddress + $Offset
        $Process = $Mapping.Process
    }
    $Process.ReadMemory($Address, $Size, $ReadAll)
}

<#
.SYNOPSIS
Writes bytes to a virtual memory region.
.DESCRIPTION
This cmdlet writes bytes to a region of virtual memory in the current process or another specified process.
.PARAMETER Address
The address location to write.
.PARAMETER Data
The data buffer to write.
.PARAMETER Process
The process to write to, defaults to current process.
.PARAMETER Mapping
Specify a mapped section object.
.PARAMETER Offset
Specify the offset into the mapped section.
.PARAMETER Win32
Specify to use the Win32 WriteProcessMemory API which will automatically change page permissions.
.OUTPUTS
int - The length of bytes successfully written.
.EXAMPLE
Write-NtVirtualMemory $addr 0, 1, 2, 3, 4
Write 5 bytes to $addr
.EXAMPLE
Write-NtVirtualMemory $addr 0, 1, 2, 3, 4 -Process $process
Write 5 bytes to $addr in another process.
.EXAMPLE
Write-NtVirtualMemory $map -Offset 100 -Data 0, 1, 2, 3, 4
Write 5 bytes to a mapping at offset 100.
#>
function Write-NtVirtualMemory {
    [CmdletBinding(DefaultParameterSetName="FromAddress")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName="FromAddress")]
        [int64]$Address,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromMapping")]
        [NtCoreLib.NtMappedSection]$Mapping,
        [parameter(ParameterSetName="FromMapping")]
        [int64]$Offset = 0,
        [parameter(Mandatory, Position = 1)]
        [byte[]]$Data,
        [parameter(ParameterSetName="FromAddress")]
        [NtCoreLib.NtProcess]$Process = [NtCoreLib.NtProcess]::Current,
        [switch]$Win32
    )

    if ($PSCmdlet.ParameterSetName -eq "FromMapping") {
        $Address = $Mapping.BaseAddress + $Offset
        $Process = $Mapping.Process
    }

    if ($Win32) {
        [NtCoreLib.Win32.Memory.Win32MemoryUtils]::WriteMemory($Process, $Address, $Data)
    } else {
        $Process.WriteMemory($Address, $Data)
    }
}
