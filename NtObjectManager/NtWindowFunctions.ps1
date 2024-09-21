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
Get the names of the Windows Stations in the current Session.
.DESCRIPTION
This cmdlet queries the names of the Window Stations in the current Session.
.PARAMETER Current
Show the current Window Station name only.
.INPUTS
string
.OUTPUTS
None
#>
function Get-NtWindowStationName {
    Param(
        [Parameter()]
        [switch]$Current
    )

    if ($Current) {
        [NtCoreLib.NtWindowStation]::Current.Name | Write-Output
    }
    else {
        [NtCoreLib.NtWindowStation]::WindowStations | Write-Output
    }
}

<#
.SYNOPSIS
Gets the names of the Desktops from the specified Window Station.
.DESCRIPTION
This cmdlet queries the names of the Desktops from the specified Window Station.
By default will use the current process Window Station.
.PARAMETER WindowStation
The Window Station to query.
.PARAMETER Current
Specify to get the name of the current thread desktop.
.PARAMETER ThreadId
Specify to get the name of the desktop from a thread.
.INPUTS
string
.OUTPUTS
None
#>
function Get-NtDesktopName {
    [CmdletBinding(DefaultParameterSetName = "FromCurrentWindowStation")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromWindowStation")]
        [NtCoreLib.NtWindowStation]$WindowStation,
        [Parameter(ParameterSetName = "FromCurrentDesktop")]
        [switch]$Current,
        [Parameter(ParameterSetName = "FromThreadId")]
        [alias("tid")]
        [int]$ThreadId
    )

    switch ($PSCmdlet.ParameterSetName) {
        "FromCurrentWindowStation" {
            $winsta = [NtCoreLib.NtWindowStation]::Current
            $winsta.Desktops | Write-Output
        }
        "FromWindowStation" {
            $WindowStation.Desktops | Write-Output
        }
        "FromCurrentDesktop" {
            [NtCoreLib.NtDesktop]::Current.Name | Write-Output
        }
        "FromThreadId" {
            [NtCoreLib.NtDesktop]::GetThreadDesktop($ThreadId).Name | Write-Output
        }
    }
}

<#
.SYNOPSIS
Gets the a list of Window handles.
.DESCRIPTION
This cmdlet queries the list of Window Handles based on a set of criteria such as Desktop or ThreadId.
.PARAMETER Desktop
The Desktop to query.
.PARAMETER Parent
Specify the parent Window if enumerating children.
.PARAMETER Children
Specify the get list of child windows.
.PARAMETER Immersive
Specify to get immersive Windows.
.PARAMETER ThreadId
Specify the thread ID for the Window.
.PARAMETER ProcessId
Specify the process ID for the Window.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtWindow
#>
function Get-NtWindow {
    [CmdletBinding()]
    Param(
        [NtCoreLib.NtDesktop]$Desktop,
        [switch]$Children,
        [switch]$Immersive,
        [NtCoreLib.NtWindow]$Parent = [NtCoreLib.NtWindow]::Null,
        [alias("tid")]
        [int]$ThreadId,
        [alias("pid")]
        [int]$ProcessId
    )

    $ws = [NtCoreLib.NtWindow]::GetWindows($Desktop, $Parent, $Children, !$Immersive, $ThreadId)
    if ($ProcessId -ne 0) {
         $ws = $ws | Where-Object ProcessId -eq $ProcessId
    }
    $ws | Write-Output
}

<#
.SYNOPSIS
Send a message to a Window handle.
.DESCRIPTION
This cmdlet sends a message to a window handle.
.PARAMETER Window
The Window to send to.
.PARAMETER Message
Specify the message to send.
.PARAMETER WParam
Specify the WPARAM value.
.PARAMETER LParam
Specify the LPARAM value.
.PARAMETER Wait
Specify to send the message and wait rather than post.
.PARAMETER Ansi
Specify to send the message as ANSI rather than Unicode.
.INPUTS
None
.OUTPUTS
System.IntPtr
#>
function Send-NtWindowMessage {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtCoreLib.NtWindow[]]$Window,
        [Parameter(Mandatory, Position = 1)]
        [int]$Message,
        [Parameter(Position = 2)]
        [IntPtr]$WParam = [IntPtr]::Zero,
        [Parameter(Position = 3)]
        [IntPtr]$LParam = [IntPtr]::Zero,
        [switch]$Wait,
        [switch]$Ansi
    )

    PROCESS {
        foreach($w in $Window) {
            if ($Wait) {
                if ($Ansi) {
                    $w.SendMessageAnsi($Message, $WParam, $LParam) | Write-Output
                } else {
                    $w.SendMessage($Message, $WParam, $LParam) | Write-Output
                }
            } else {
                if ($Ansi) {
                    $w.PostMessageAnsi($Message, $WParam, $LParam)
                } else {
                    $w.PostMessage($Message, $WParam, $LParam)
                }
            }
        }
    }
}

<#
.SYNOPSIS
Get an ATOM object.
.DESCRIPTION
This cmdlet gets all ATOM objects or by name or atom.
.PARAMETER Atom
Specify the ATOM to get.
.PARAMETER Name
Specify the name of the ATOM to get.
.PARAMETER User
Specify to get a user atom rather than a global.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtAtom
#>
function Get-NtAtom {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [Parameter(Mandatory, ParameterSetName = "FromAtom")]
        [uint16]$Atom,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromName")]
        [string]$Name,
        [Parameter(ParameterSetName = "All")]
        [Parameter(ParameterSetName = "FromAtom")]
        [switch]$User
    )

    switch ($PSCmdlet.ParameterSetName) {
        "All" { [NtCoreLib.NtAtom]::GetAtoms(!$User) | Write-Output }
        "FromAtom" { [NtCoreLib.NtAtom]::Open($Atom, $true, !$User, $true).Result | Write-Output }
        "FromName" { [NtCoreLib.NtAtom]::Find($Name) | Write-Output }
    }
}

<#
.SYNOPSIS
Add a ATOM object.
.DESCRIPTION
This cmdlet adds an ATOM objects.
.PARAMETER Name
Specify the name of the ATOM to add.
.PARAMETER Flags
Specify the flags for the ATOM.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtAtom
#>
function Add-NtAtom {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,
        [NtCoreLib.AddAtomFlags]$Flags = 0
    )

    [NtCoreLib.NtAtom]::Add($Name, $Flags) | Write-Output
}

<#
.SYNOPSIS
Removes an ATOM object.
.DESCRIPTION
This cmdlet removes an ATOM object by name or atom.
.PARAMETER Object
Specify the NtAtom object to remove.
.PARAMETER Atom
Specify the ATOM to remove.
.PARAMETER Name
Specify the name of the ATOM to remove.
.INPUTS
None
.OUTPUTS
None
#>
function Remove-NtAtom {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromObject")]
        [NtCoreLib.NtAtom]$Object,
        [Parameter(Mandatory, ParameterSetName = "FromAtom")]
        [uint16]$Atom,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromName")]
        [string]$Name
    )

    $obj = switch ($PSCmdlet.ParameterSetName) {
        "FromObject" { $Object }
        "FromAtom" { Get-NtAtom -Atom $Atom }
        "FromName" { Get-NtATom -Name $Name }
    }

    if ($null -ne $obj) {
        $obj.Delete()
    }
}
