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
Export details about an object to re-import in another process.
.DESCRIPTION
This function generates a short JSON string which can be used to duplicate into another process
using the Import-NtObject function. The handle must be valid when the import function is executed.
.PARAMETER Object
Specify the object to export.
.OUTPUTS
string
.EXAMPLE
Export-NtObject $obj
Export an object to a JSON string.
#>
function Export-NtObject {
    param(
        [Parameter(Position = 0, Mandatory = $true)]
        [NtCoreLib.NtObject]$Object
    )
    $obj = [PSCustomObject]@{ProcessId = $PID; Handle = $Object.Handle.DangerousGetHandle().ToInt32() }
    $obj | ConvertTo-Json -Compress
}

<#
.SYNOPSIS
Imports an object exported with Export-NtObject.
.DESCRIPTION
This function accepts a JSON string exported from Export-NtObject which allows an object to be
duplicated between PowerShell instances. You can also specify the PID and handle separetly.
.PARAMETER Object
Specify the object to import as a JSON string.
.PARAMETER ProcessId
Specify the process ID to import from.
.PARAMETER Handle
Specify the handle value to import from.
.OUTPUTS
NtCoreLib.NtObject (the best available type).
.EXAMPLE
Import-NtObject '{"ProcessId":3300,"Handle":2660}'
Import an object from a JSON string.
.EXAMPLE
Import-NtObject -ProcessId 3300 -Handle 2660
Import an object from separate PID and handle values.
#>
function Import-NtObject {
    [CmdletBinding(DefaultParameterSetName = "FromObject")]
    param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromObject")]
        [string]$Object,
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromPid")]
        [int]$ProcessId,
        [Parameter(Position = 1, Mandatory, ParameterSetName = "FromPid")]
        [int]$Handle
    )
    switch ($PSCmdlet.ParameterSetName) {
        "FromObject" {
            $obj = ConvertFrom-Json $Object
            Import-NtObject -ProcessId $obj.ProcessId -Handle $obj.Handle
        }
        "FromPid" {
            Use-NtObject($generic = [NtCoreLib.NtGeneric]::DuplicateFrom($ProcessId, $Handle)) {
                $generic.ToTypedObject()
            }
        }
    }
}

<#
.SYNOPSIS
Resolve the address of a list of objects.
.DESCRIPTION
This cmdlet resolves the kernel address for a list of objects. This is an expensive operation so it's designed to be
called with a list.
.PARAMETER Objects
The list of objects to resolve.
.PARAMETER PassThru
Write the object addresses to the object. Normally no output is generated.
.OUTPUTS
Int64 - If PassThru specified.
.EXAMPLE
Resolve-NtObjectAddress $obj1, $obj2; $obj1.Address
Resolve the address of two objects.
#>
function Resolve-NtObjectAddress {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [NtCoreLib.NtObject[]]$Objects,
        [switch]$PassThru
    )
    BEGIN {
        $objs = @()
    }
    PROCESS {
        $objs += $Objects
    }
    END {
        [NtCoreLib.NtSystemInfo]::ResolveObjectAddress([NtCoreLib.NtObject[]]$objs)
        if ($PassThru) {
            $objs | Select-Object -ExpandProperty Address | Write-Output
        }
    }
}

<#
.SYNOPSIS
Gets an object from a handle in the current process.
.DESCRIPTION
This cmdlet creates an object for a handle in the current process.
.PARAMETER Handle
Specify the handle in the current process.
.PARAMETER OwnsHandle
Specify the own the handle (closed when object is disposed).
.INPUTS
None
.OUTPUTS
NtCoreLib.NtObject
.EXAMPLE
Get-NtObjectFromHandle -Handle 0x1234
Get an object from handle 0x1234.
.EXAMPLE
Get-NtObjectFromHandle -Handle 0x1234 -OwnsHandle
Get an object from handle 0x1234 and owns the handle.
#>
function Get-NtObjectFromHandle {
    Param(
        [parameter(Mandatory, Position = 0)]
        [IntPtr]$Handle,
        [switch]$OwnsHandle
    )

    $temp_handle = [NtCoreLib.Native.SafeHandles.SafeKernelObjectHandle]::new($Handle, $false)
    [NtCoreLib.NtType]::GetTypeForHandle($temp_handle, $true).FromHandle($Handle, $OwnsHandle)
}

<#
.SYNOPSIS
Close an object handle.
.DESCRIPTION
This cmdlet closes an object handle. It supports closing a handle locally or in another process as long
as duplicate handle access is granted.
.PARAMETER Object
Specify the object to close.
.PARAMETER Process
Specify the process where the handle to close is located.
.PARAMETER ProcessId
Specify the process ID where the handle to close is located.
.PARAMETER Handle
Specify the handle value to close in another process.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Close-NtObject -Object $obj
Close an object in the current process.
.EXAMPLE
Close-NtObject -Handle 0x1234 -Process $proc
Close handle 0x1234 in another process.
.EXAMPLE
Close-NtObject -Handle 0x1234 -ProcessId 684
Close handle 0x1234 in process with ID 684.
.EXAMPLE
Close-NtObject -Handle 0x1234
Close handle 0x1234 in process the current process.
#>
function Close-NtObject {
    [CmdletBinding(DefaultParameterSetName = "FromProcess")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromObject", ValueFromPipeline)]
        [NtCoreLib.NtObject]$Object,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromProcess")]
        [NtCoreLib.NtProcess]$Process,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromProcessId")]
        [int]$ProcessId,
        [parameter(Mandatory, Position = 1, ParameterSetName = "FromProcess")]
        [parameter(Mandatory, Position = 1, ParameterSetName = "FromProcessId")]
        [parameter(Mandatory, Position = 1, ParameterSetName = "FromCurrentProcess")]
        [IntPtr]$Handle,
        [parameter(Mandatory, ParameterSetName = "FromCurrentProcess")]
        [parameter(Mandatory, ParameterSetName = "FromCurrentProcessSafe")]
        [switch]$CurrentProcess,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromCurrentProcessSafe")]
        [NtCoreLib.Native.SafeHandles.SafeKernelObjectHandle]$SafeHandle
    )

    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "FromObject" { $Object.Close() }
            "FromProcess" { [NtCoreLib.NtObject]::CloseHandle($Process, $Handle) }
            "FromProcessId" { [NtCoreLib.NtObject]::CloseHandle($ProcessId, $Handle) }
            "FromCurrentProcess" { [NtCoreLib.NtObject]::CloseHandle($Handle) }
            "FromCurrentProcessSafe" { [NtCoreLib.NtObject]::CloseHandle($SafeHandle) }
        }
    }
}

<#
.SYNOPSIS
Gets the information classes for a type.
.DESCRIPTION
This cmdlet gets the list of information classes for a type. You can get the query and set information classes.
.PARAMETER Type
The NT type to get information classes for.
.PARAMETER Object
The object to get information classes for.
.PARAMETER Set
Specify to get the set information classes which might differ.
.PARAMETER Volume
Specify to get the volume information classes.
.INPUTS
None
.OUTPUTS
KeyPair<string, int>[]
#>
function Get-NtObjectInformationClass {
    [CmdletBinding(DefaultParameterSetName = "FromType")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromType")]
        [NtCoreLib.NtType]$Type,
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromObject")]
        [NtCoreLib.NtObject]$Object,
        [Parameter(ParameterSetName = "FromObject")]
        [Parameter(ParameterSetName = "FromType")]
        [switch]$Set,
        [Parameter(ParameterSetName = "FromVolume")]
        [switch]$Volume
    )

    if ($Volume) {
        [NtObjectManager.Utils.PSUtils]::GetFsVolumeInfoClass() | Write-Output
    } else {
        if ($PSCmdlet.ParameterSetName -eq "FromObject") {
            $Type = $Object.NtType
        }

        if ($Set) {
            $Type.SetInformationClass | Write-Output
        }
        else {
            $Type.QueryInformationClass | Write-Output
        }
    }
}

<#
.SYNOPSIS
Compares two object handles to see if they're the same underlying object.
.DESCRIPTION
This cmdlet compares two handles to see if they're the same underlying object.
On Window 10 this is a supported operation, for downlevel queries the address for
the objects and compares that instead.
.PARAMETER Left
The left hand object to compare.
.PARAMETER Right
The right hand object to compare.
.INPUTS
None
.OUTPUTS
bool
#>
function Compare-NtObject {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.NtObject]$Left,
        [Parameter(Position = 1, Mandatory)]
        [NtCoreLib.NtObject]$Right
    )
    $Left.SameObject($Right) | Write-Output
}

<#
.SYNOPSIS
Test if an object can be opened.
.DESCRIPTION
This cmdlet tests if an object exists by opening it. This might give false negatives
if the reason for not opening it was unrelated to it not existing.
.PARAMETER Path
Specify an object path to get the security descriptor from.
.PARAMETER TypeName
Specify the type name of the object at Path. Needed if the module cannot automatically determine the NT type to open.
.PARAMETER Root
Specify a root object for Path.
.INPUTS
None
.OUTPUTS
Boolean
.EXAMPLE
Test-NtObject \BaseNamedObjects\ABC
Test if \BaseNamedObjects\ABC can be opened.
.EXAMPLE
Test-NtObject ABC -Root $dir
Test if ABC can be opened relative to $dir.
.EXAMPLE
Test-NtObject \BaseNamedObjects\ABC -TypeName Mutant.
Test if \BaseNamedObjects\ABC can be opened with a File type.
#>
function Test-NtObject {
    [CmdletBinding(DefaultParameterSetName = "FromPath")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromPath")]
        [string]$Path,
        [parameter(ParameterSetName = "FromPath")]
        [string]$TypeName,
        [parameter(ParameterSetName = "FromPath")]
        [NtCoreLib.NtObject]$Root
    )
    switch ($PsCmdlet.ParameterSetName) {
        "FromPath" {
            try {
                Use-NtObject($obj = Get-NtObject -Path $Path -Root $Root -TypeName $TypeName) { }
                return $true
            } 
            catch {
                return $false
            }
        }
    }
}

<#
.SYNOPSIS
Create a new object attributes structure.
.DESCRIPTION
This cmdlet creates a new object attributes structure based on its parameters. Note you should dispose of the object
attributes afterwards.
.PARAMETER Name
Optional NT native name for the object
.PARAMETER Root
Optional NT object root for relative paths
.PARAMETER Attributes
Optional object attributes flags
.PARAMETER SecurityQualityOfService
Optional security quality of service flags
.PARAMETER SecurityDescriptor
Optional security descriptor
.PARAMETER Sddl
Optional security descriptor in SDDL format
.INPUTS
None
.EXAMPLE
New-NtObjectAttributes \??\c:\windows
Create a new object attributes for \??\C:\windows
#>
function New-NtObjectAttributes {
    Param(
        [Parameter(Position = 0)]
        [string]$Name,
        [NtCoreLib.NtObject]$Root,
        [NtCoreLib.AttributeFlags]$Attributes = "None",
        [NtCoreLib.Security.Token.SecurityQualityOfService]$SecurityQualityOfService,
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [string]$Sddl
    )

    $sd = $SecurityDescriptor
    if ($Sddl -ne "") {
        $sd = New-NtSecurityDescriptor -Sddl $Sddl
    }

    [NtCoreLib.ObjectAttributes]::new($Name, $Attributes, [NtCoreLib.NtObject]$Root, $SecurityQualityOfService, $sd)
}
