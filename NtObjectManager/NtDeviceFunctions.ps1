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
Open a filter communications port.
.DESCRIPTION
This cmdlet opens a filter communication port by name.
.PARAMETER Path
Specify the path to the filter communication port.
.PARAMETER SyncHandle
Specify to make the handle synchronous.
.PARAMETER Context
Specify optional context buffer.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Filter.FilterConnectionPort
.EXAMPLE
Get-FilterConnectionPort -Path "\FilterDriver"
Open the filter communication port named \FilterDriver.
#>
function Get-FilterConnectionPort {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$Path,
        [switch]$SyncHandle,
        [byte[]]$Context = $null
    )

    [NtCoreLib.Win32.Filter.FilterConnectionPort]::Open($Path, $SyncHandle, $Context) | Write-Output
}

<#
.SYNOPSIS
Sends a message to a filter connection port.
.DESCRIPTION
This cmdlet sends and receives a message on a filter connection port.
.PARAMETER Port
Specify the port to send on.
.PARAMETER Input
Optional input data.
.PARAMETER MaximumOutput
Specify maximum output data.
.INPUTS
None
.OUTPUTS
byte[]
.EXAMPLE
Send-FilterConnectionPort -Port $port -Input @(1, 2, 3, 4) -MaximumOutput 100
Send a 4 byte message and receive at most 100 bytes.
#>
function Send-FilterConnectionPort {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Filter.FilterConnectionPort]$Port,
        [byte[]]$Input = $null,
        [int]$MaximumOutput = 0
    )

    $Port.SendMessage($Input, $MaximumOutput) | Write-Output -NoEnumerate
}

<#
.SYNOPSIS
Get list of filter drivers loaded on the system.
.DESCRIPTION
This cmdlet enumerates the list of filter drivers loaded on the system.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Filter.FilterDriver[]
.EXAMPLE
Get-FilterDriver
Get list of filter drivers.
#>
function Get-FilterDriver {
    [NtCoreLib.Win32.Filter.FilterManagerUtils]::GetFilterDrivers() | Write-Output
}

<#
.SYNOPSIS
Get list of filter driver instances on the system.
.DESCRIPTION
This cmdlet enumerates the list of filter driver instances for a specified filter driver.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Filter.FilterInstance[]
.EXAMPLE
Get-FilterDriverInstance 
Get list of filter driver instances for all filter drivers.
.EXAMPLE
Get-FilterDriverInstance -FilterName "luafv"
Get list of filter driver instances for the "luafv" driver.
#>
function Get-FilterDriverInstance {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromName")]
        [string]$FilterName
    )

    switch($PSCmdlet.ParameterSetName) {
        "All" {
            [NtCoreLib.Win32.Filter.FilterManagerUtils]::GetFilterDriverInstances() | Write-Output
        }
        "FromName" {
            [NtCoreLib.Win32.Filter.FilterManagerUtils]::GetFilterDriverInstances($FilterName) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get list of filter driver instances on the system.
.DESCRIPTION
This cmdlet enumerates the list of filter driver instances for a specified filter driver.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Filter.FilterVolume[]
.EXAMPLE
Get-FilterDriverVolume 
Get list of filter driver volumes.
#>
function Get-FilterDriverVolume {
    [NtCoreLib.Win32.Filter.FilterManagerUtils]::GetFilterVolumes() | Write-Output
}

<#
.SYNOPSIS
Get list of filter driver volume instances on the system.
.DESCRIPTION
This cmdlet enumerates the list of filter driver volume instances for a specified filter driver.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Filter.FilterInstance[]
.EXAMPLE
Get-FilterDriverVolumeInstance 
Get list of filter driver instances for all filter driver volumes.
.EXAMPLE
Get-FilterDriverInstance -VolumeName "C:\"
Get list of filter driver volume instances for the C: drive.
#>
function Get-FilterDriverVolumeInstance {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromName")]
        [string]$VolumeName
    )

    switch($PSCmdlet.ParameterSetName) {
        "All" {
            [NtCoreLib.Win32.Filter.FilterManagerUtils]::GetFilterVolumeInstances() | Write-Output
        }
        "FromName" {
            [NtCoreLib.Win32.Filter.FilterManagerUtils]::GetFilterVolumeInstances($VolumeName) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get the device setup classes.
.DESCRIPTION
This cmdlet gets device setup classes, either all installed or from a GUID/Name.
.PARAMETER Name
The name of the setup class.
.PARAMETER Class
The GUID of the setup class.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Device.DeviceSetupClass
.EXAMPLE
Get-NtDeviceSetupClass
Get all device setup classes.
.EXAMPLE
Get-NtDeviceSetupClass -Class '6BDD1FC1-810F-11D0-BEC7-08002BE20920'
Get the device setup class for the specified GUID.
.EXAMPLE
Get-NtDeviceSetupClass -Name 'USB'
Get the device setup class for the USB class.
#>
function Get-NtDeviceSetupClass {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromName")]
        [string]$Name,
        [parameter(Mandatory, ParameterSetName = "FromClass", ValueFromPipelineByPropertyName)]
        [guid]$Class
    )

    PROCESS {
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceSetupClasses() | Write-Output
            }
            "FromName" {
                [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceSetupClasses() | Where-Object Name -eq $Name | Write-Output
            }
            "FromClass" {
                [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceSetupClass($Class) | Write-Output
            }
        }
    }
}

<#
.SYNOPSIS
Get the device interface classes.
.DESCRIPTION
This cmdlet gets device interface classes, either all installed or from a GUID.
.PARAMETER Class
The GUID of the interface class.
.PARAMETER All
Get all devices including ones not present.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Device.DeviceInterfaceClass
.EXAMPLE
Get-NtDeviceInterfaceClass
Get all device interface classes.
.EXAMPLE
Get-NtDeviceInterfaceClass -Class '6BDD1FC1-810F-11D0-BEC7-08002BE20920'
Get the device interface class for the specified GUID.
#>
function Get-NtDeviceInterfaceClass {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromClass")]
        [guid]$Class,
        [switch]$All
    )

    switch($PSCmdlet.ParameterSetName) {
        "All" {
            [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceInterfaceClasses($All) | Write-Output
        }
        "FromClass" {
            [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceInterfaceClass($Class, $All) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get the device node.
.DESCRIPTION
This cmdlet gets device nodes, either all present or from a GUID/Name.
.PARAMETER Class
The GUID of the setup class.
.PARAMETER All
Get all device instances. The default is to only get present instances.
.PARAMETER Tree
Get all device nodes as a tree.
.PARAMETER InstanceId
Get device from instance ID.
.PARAMETER LinkName
Specify a symbolic link name to resolve the device node.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Device.DeviceNode
.EXAMPLE
Get-NtDeviceNode
Get all present device instances.
.EXAMPLE
Get-NtDeviceNode -All
Get all device instances.
.EXAMPLE
Get-NtDeviceNode -Class '6BDD1FC1-810F-11D0-BEC7-08002BE20920'
Get the device instances class for the specified setup class GUID.
.EXAMPLE
Get-NtDeviceNode -Tree
Get all device instances in a tree structure.
.EXAMPLE
Get-NtDeviceNode -PDOName \Device\HarddiskVolume3
Get the device node with a specified PDO.
.EXAMPLE
Get-NtDeviceNode -LinkName \??\C: 
Get the device node with a specified symbolic link.
#>
function Get-NtDeviceNode {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromClass", ValueFromPipelineByPropertyName)]
        [guid]$Class,
        [parameter(ParameterSetName = "FromClass")]
        [parameter(ParameterSetName = "All")]
        [switch]$All,
        [parameter(Mandatory, ParameterSetName = "FromTree")]
        [switch]$Tree,
        [parameter(Mandatory, ParameterSetName = "FromInstanceId")]
        [string]$InstanceId,
        [parameter(Mandatory, ParameterSetName = "FromPDOName")]
        [string]$PDOName,
        [parameter(ParameterSetName = "FromLinkName")]
        [string]$LinkName
    )

    PROCESS {
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceNodeList($All) | Write-Output
            }
            "FromClass" {
                [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceNodeList($Class, $All) | Write-Output
            }
            "FromTree" {
                [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceNodeTree() | Write-Output
            }
            "FromInstanceId" {
                [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceNode($InstanceId) | Write-Output
            }
            "FromPDOName" {
                Get-NtDeviceNode | Where-Object PDOName -eq $PDOName
            }
            "FromLinkName" {
                try { 
                    $PDOName = Get-NtSymbolicLinkTarget -Path $LinkName -Resolve
                    Get-NtDeviceNode | Where-Object PDOName -eq $PDOName
                } catch {
                    Write-Error $_
                }
            }
        }
    }
}

<#
.SYNOPSIS
Get device properties.
.DESCRIPTION
This cmdlet gets device properties.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Device.DeviceProperty[]
.EXAMPLE
Get-NtDeviceProperty -Device $dev
Get all properties for a device.
#>
function Get-NtDeviceProperty {
    [CmdletBinding(DefaultParameterSetName = "FromDevice")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromDevice", ValueFromPipeline)]
        [NtCoreLib.Win32.Device.IDevicePropertyProvider]$Device
    )

    PROCESS {
        switch($PSCmdlet.ParameterSetName) {
            "FromDevice" {
                $Device.GetProperties() | Write-Output
            }
        }
    }
}

<#
.SYNOPSIS
Get device node children.
.DESCRIPTION
This cmdlet gets device node children.
.PARAMETER Node
The device node to query the children for.
.PARAMETER Recurse
Recursively get child nodes.
.PARAMETER Depth
Specify the maximum depth for the recursion.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Device.DeviceTreeNode[]
.EXAMPLE
Get-NtDeviceNodeChild -Node $dev
Get all children for a device node
.EXAMPLE
Get-NtDeviceNodeChild -Node $dev -Recurse
Get all children for a device node recursively.
.EXAMPLE
Get-NtDeviceNodeChild -Node $dev -Recurse -Depth 2
Get all children for a device node recursively with max depth of 2.
#>
function Get-NtDeviceNodeChild {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromNode", Position = 0)]
        [NtCoreLib.Win32.Device.DeviceNode]$Node,
        [switch]$Recurse,
        [int]$Depth = [int]::MaxValue
    )

    if ($Recurse -and $Depth -lt 1) {
        return
    }

    try
    {
        if ($Node -isNot [NtCoreLib.Win32.Device.DeviceTreeNode]) {
            $Node = [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceNodeTree($Node.InstanceId)
        }

        switch($PSCmdlet.ParameterSetName) {
            "FromNode" {
                if ($Recurse) {
                    $recdepth = $Depth - 1
                    $Device.Children | ForEach-Object { Get-NtDeviceNodeChild -Node $_ -Recurse -Depth $recdepth }
                }
                $Node.Children | Write-Output
            }
        }
    }
    catch 
    {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get device instance parent.
.DESCRIPTION
This cmdlet gets device node parent.
.PARAMETER Node
The device node to query the parent for.
.PARAMETER Recurse
Get all parents recursively.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Device.DeviceNode[]
.EXAMPLE
Get-NtDeviceNodeParent -Node $dev
Get parent for device node.
.EXAMPLE
Get-NtDeviceNodeParent -Node $dev -Recurse
Get all parents for device node.
#>
function Get-NtDeviceNodeParent {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromNode", Position = 0)]
        [NtCoreLib.Win32.Device.DeviceNode]$Node,
        [switch]$Recurse
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromNode" {
            if ($Recurse) {
                $Node.GetParentNodes() | Write-Output
            } else {
                $Node.Parent | Write-Output
            }
        }
    }
}

<#
.SYNOPSIS
Get device stack for a node.
.DESCRIPTION
This cmdlet gets device node's device stack.
.PARAMETER Node
The device node to query device stack for.
.PARAMETER Summary
Summarize the device stack as a single line.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Device.DeviceStackEntry[]
.EXAMPLE
Get-NtDeviceNodeStack -Node $dev
Get device stack for device node.
#>
function Get-NtDeviceNodeStack {
    [CmdletBinding(DefaultParameterSetName = "FromNode")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromNode", Position = 0, ValueFromPipeline)]
        [NtCoreLib.Win32.Device.DeviceNode]$Node,
        [switch]$Summary
    )

    PROCESS {
        switch($PSCmdlet.ParameterSetName) {
            "FromNode" {
                if ($Summary) {
                    [string]::Join(", ", $Node.DeviceStack) | Write-Output
                } else {
                    $Node.DeviceStack | Write-Output
                }
            }
        }
    }
}

<#
.SYNOPSIS
Get the device interface instances.
.DESCRIPTION
This cmdlet gets device interface instances either all present, from a GUID or instance name.
.PARAMETER Class
The GUID of the interface class.
.PARAMETER Instance
The path the instance symbolic link.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Device.DeviceInterfaceInstance[]
.EXAMPLE
Get-NtDeviceInterfaceInstance
Get all device interface instances.
.EXAMPLE
Get-NtDeviceInterfaceInstance -Class '6BDD1FC1-810F-11D0-BEC7-08002BE20920'
Get the device interface instances for the specified GUID.
.EXAMPLE
Get-NtDeviceInterfaceInstance -Instance '\\?\HSIDS&1234'
Get the device interface instances for the instance symbolic link path.
#>
function Get-NtDeviceInterfaceInstance {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromClass")]
        [guid]$Class,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromInstance")]
        [string]$Instance
    )

    switch($PSCmdlet.ParameterSetName) {
        "All" {
            [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceInterfaceInstances() | Write-Output
        }
        "FromClass" {
            [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceInterfaceInstances($Class) | Write-Output
        }
        "FromInstance" {
            [NtCoreLib.Win32.Device.DeviceUtils]::GetDeviceInterfaceInstance($Instance) | Write-Output
        }
    }
}
