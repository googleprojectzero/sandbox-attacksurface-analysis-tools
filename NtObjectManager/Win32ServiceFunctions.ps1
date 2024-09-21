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
Create a new Win32 service.
.DESCRIPTION
This cmdlet creates a new Win32 service. This is similar New-Service but it exposes
all the options from the CreateService API and allows you to specify service users.
.PARAMETER Name
Specify the name of the service.
.PARAMETER DisplayName
Specify the display name for the service.
.PARAMETER Type
Specify the service type.
.PARAMETER Start
Specify the service start type.
.PARAMETER Path
Specify the path to the service binary.
.PARAMETER LoadOrderGroup
Specify the load order group.
.PARAMETER Dependencies
Specify the list of dependencies.
.PARAMETER Username
Specify the username for the service.
.PARAMETER Password
Specify the password for the username.
.PARAMETER PassThru
Specify to return information about the service.
.PARAMETER MachineName
Specify the target computer.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Service.ServiceInstance
#>
function New-Win32Service {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position = 0)]
        [string]$Name,
        [string]$DisplayName,
        [NtCoreLib.Win32.Service.ServiceType]$Type = "Win32OwnProcess",
        [NtCoreLib.Win32.Service.ServiceStartType]$Start = "Demand",
        [NtCoreLib.Win32.Service.ServiceErrorControl]$ErrorControl = 0,
        [parameter(Mandatory, Position = 1)]
        [string]$Path,
        [string]$LoadOrderGroup,
        [string[]]$Dependencies,
        [string]$Username,
        [NtObjectManager.Utils.PasswordHolder]$Password,
        [switch]$PassThru,
        [string]$MachineName
    )

    $pwd = if ($null -ne $Password) {
        $Password.Password
    }
    $service = [NtCoreLib.Win32.Service.ServiceUtils]::CreateService($MachineName, $Name, $DisplayName, $Type, `
        $Start, $ErrorControl, $Path, $LoadOrderGroup, $Dependencies, $Username, $pwd)
    if ($PassThru) {
        $service
    }
}

<#
.SYNOPSIS
Delete a Win32 service.
.DESCRIPTION
This cmdlet deletes a Win32 service. This is basically the same as Remove-Service
but is available on PowerShell 5.1. Also directly supports specifying the machine name.
.PARAMETER Name
Specify the name of the service.
.PARAMETER MachineName
Specify the target computer.
.INPUTS
None
.OUTPUTS
None
#>
function Remove-Win32Service {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position = 0)]
        [string]$Name,
        [string]$MachineName
    )

    [NtCoreLib.Win32.Service.ServiceUtils]::DeleteService($MachineName, $Name)
}

<#
.SYNOPSIS
Get the security descriptor for a service.
.DESCRIPTION
This cmdlet gets the security descriptor for a service or the SCM.
.PARAMETER Name
Specify the name of the service.
.PARAMETER ServiceControlManager
Specify to query the service control manager security descriptor.
.PARAMETER SecurityInformation
Specify the parts of the security descriptor to return.
.PARAMETER MachineName
Specify the target computer.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.SecurityDescriptor
#>
function Get-Win32ServiceSecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName="FromName")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName="FromName")]
        [string]$Name,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromScm")]
        [switch]$ServiceControlManager,
        [parameter(Position = 1)]
        [NtCoreLib.Security.Authorization.SecurityInformation]$SecurityInformation = "Owner, Group, Dacl, Label",
        [string]$MachineName
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromName" {
            [NtCoreLib.Win32.Service.ServiceUtils]::GetServiceSecurityDescriptor($MachineName, $Name, $SecurityInformation)
        }
        "FromScm" {
            [NtCoreLib.Win32.Service.ServiceUtils]::GetScmSecurityDescriptor($MachineName, $SecurityInformation)
        }
    }
}

<#
.SYNOPSIS
Set the security descriptor for a service.
.DESCRIPTION
This cmdlet sets the security descriptor for a service or the SCM.
.PARAMETER Name
Specify the name of the service.
.PARAMETER ServiceControlManager
Specify to set the service control manager security descriptor.
.PARAMETER SecurityInformation
Specify the parts of the security descriptor to set.
.PARAMETER SecurityDescriptor 
The security descriptor to set.
.PARAMETER MachineName
Specify the target computer.
.INPUTS
None
.OUTPUTS
None
#>
function Set-Win32ServiceSecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName="FromName")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName="FromName")]
        [string]$Name,
        [parameter(Mandatory, ParameterSetName="FromScm")]
        [switch]$ServiceControlManager,
        [parameter(Mandatory, Position = 1)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [parameter(Mandatory, Position = 2)]
        [NtCoreLib.Security.Authorization.SecurityInformation]$SecurityInformation,
        [string]$MachineName
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromName" {
            [NtCoreLib.Win32.Service.ServiceUtils]::SetServiceSecurityDescriptor($MachineName, $Name, $SecurityDescriptor, $SecurityInformation)
        }
        "FromScm" {
            [NtCoreLib.Win32.Service.ServiceUtils]::SetScmSecurityDescriptor($MachineName, $SecurityDescriptor, $SecurityInformation)
        }
    }
}

<#
.SYNOPSIS
Start a Win32 service.
.DESCRIPTION
This cmdlet starts a Win32 service. This is basically the same as Start-Service
but allows the user to specify the arguments to pass to the start callback.
.PARAMETER Name
Specify the name of the service.
.PARAMETER ArgumentList
Specify the list of arguments to the service.
.PARAMETER PassThru
Query for the service status after starting.
.PARAMETER MachineName
Specify the target computer.
.PARAMETER NoWait
Specify to not wait 30 seconds for the service to start.
.PARAMETER Trigger
Specify to try and use a service trigger to start the service.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Service.ServiceInstance
#>
function Start-Win32Service {
    [CmdletBinding(DefaultParameterSetName="FromStart")]
    param (
        [parameter(Mandatory, Position = 0)]
        [string]$Name,
        [parameter(ParameterSetName="FromStart")]
        [string[]]$ArgumentList,
        [parameter(ParameterSetName="FromStart")]
        [string]$MachineName,
        [parameter(Mandatory, ParameterSetName="FromTrigger")]
        [switch]$Trigger,
        [switch]$PassThru,
        [switch]$NoWait
    )

    try {
        switch ($PSCmdlet.ParameterSetName) {
            "FromStart" {
                [NtCoreLib.Win32.Service.ServiceUtils]::StartService($MachineName, $Name, $ArgumentList)
            }
            "FromTrigger" {
                $service_trigger = Get-Win32ServiceTrigger -Name $Name -Action Start | Select-Object -First 1
                if ($null -eq $service_trigger) {
                    throw "No service trigger available for $Name"
                }
                $service_trigger.Trigger()
            }
        }
        
        if (!$NoWait) {
            if (!(Wait-Win32Service -MachineName $MachineName -Name $Name -Status Running -TimeoutSec 30)) {
                Write-Error "Service didn't start in time."
                return
            }
        }
        if ($PassThru) {
            Get-Win32Service -Name $Name -MachineName $MachineName
        }
    }
    catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Tests a Win32 service state.
.DESCRIPTION
This cmdlet tests if a win32 service is in a fixed state.
.PARAMETER Name
Specify the name of the service.
.PARAMETER Status
Specify the status to test.
.PARAMETER MachineName
Specify the target computer.
.INPUTS
None
.OUTPUTS
Boolean
#>
function Test-Win32Service {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position = 0)]
        [string]$Name,
        [string]$MachineName,
        [parameter(Mandatory, Position = 1)]
        [NtCoreLib.Win32.Service.ServiceStatus]$Status
    )

    try {
        $service = Get-Win32Service -Name $Name -MachineName $MachineName
        return $service.Status -eq $Status
    }
    catch {
        Write-Error $_
        return $false
    }
}

<#
.SYNOPSIS
Restart a Win32 service.
.DESCRIPTION
This cmdlet restarts a Win32 service.
.PARAMETER Name
Specify the name of the service.
.PARAMETER ArgumentList
Specify the list of arguments to the service.
.PARAMETER PassThru
Query for the service status after starting.
.PARAMETER MachineName
Specify the target computer.
.PARAMETER NoWait
Specify to not wait 30 seconds for the service to start.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Service.ServiceInstance
#>
function Restart-Win32Service {
    [CmdletBinding(DefaultParameterSetName="FromStart")]
    param (
        [parameter(Mandatory, Position = 0)]
        [string]$Name,
        [parameter(ParameterSetName="FromStart")]
        [string[]]$ArgumentList,
        [parameter(ParameterSetName="FromStart")]
        [string]$MachineName,
        [switch]$PassThru,
        [switch]$NoWait
    )

    try {
        if (!(Test-Win32Service -Name $Name -MachineName $MachineName -Status Stopped)) {
            Send-Win32Service -Name $Name -MachineName $MachineName -Control Stop -ErrorAction Stop
        }

        Start-Win32Service -Name $Name -MachineName $MachineName -ArgumentList $ArgumentList -PassThru:$PassThru -NoWait:$NoWait
    }
    catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Send a control code to a Win32 service.
.DESCRIPTION
This cmdlet sends a control code to a Win32 service.
.PARAMETER Name
Specify the name of the service.
.PARAMETER Control
Specify the control code to send.
.PARAMETER CustomControl
Specify to send a custom control code. Typically in the range of 128 to 255.
.PARAMETER PassThru
Query for the service status after sending the code.
.PARAMETER MachineName
Specify the target computer.
.PARAMETER NoWait
Specify to not wait 30 seconds for the service control to be handled.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Service.ServiceInstance
#>
function Send-Win32Service {
    [CmdletBinding(DefaultParameterSetName="FromControl")]
    param (
        [parameter(Mandatory, Position = 0)]
        [string]$Name,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromControl")]
        [NtCoreLib.Win32.Service.ServiceControlCode]$Control,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromCustomControl")]
        [int]$CustomControl,
        [switch]$PassThru,
        [string]$MachineName,
        [parameter(ParameterSetName="FromControl")]
        [switch]$NoWait
    )

    try {
        $wait = switch($PSCmdlet.ParameterSetName) {
            "FromControl" {
                [NtCoreLib.Win32.Service.ServiceUtils]::ControlService($MachineName, $Name, $Control)
                !$NoWait
            }
            "FromCustomControl" {
                [NtCoreLib.Win32.Service.ServiceUtils]::ControlService($MachineName, $Name, $CustomControl)
                $false
            }
        }

        if ($wait) {
            $wait_state = switch($Control) {
                "Stop" {
                    Wait-Win32Service -MachineName $MachineName -Name $Name -Status Stopped -TimeoutSec 30
                }
                "Pause" {
                    Wait-Win32Service -MachineName $MachineName -Name $Name -Status Paused -TimeoutSec 30
                }
                "Continue" {
                    Wait-Win32Service -MachineName $MachineName -Name $Name -Status Running -TimeoutSec 30
                }
                default { 
                    # Anything else we just return success.
                    $true 
                }
            }

            if (!$wait_state) {
                Write-Error "Service didn't respond to control in time."
                return
            }
        }
        if ($PassThru) {
            Get-Win32Service -Name $Name -MachineName $MachineName
        }
    }
    catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Wait for a Win32 service status.
.DESCRIPTION
This cmdlet waits for a Win32 service to reach a certain status. Returns true if the status was reached. False if timed out or other error.
.PARAMETER Name
Specify the name of the service.
.PARAMETER Status
Specify the status to wait for.
.PARAMETER MachineName
Specify the target computer.
.PARAMETER TimeoutSec
Specify the timeout in seconds.
.INPUTS
None
.OUTPUTS
Boolean
#>
function Wait-Win32Service {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position = 0)]
        [string]$Name,
        [parameter(Mandatory, Position = 1)]
        [NtCoreLib.Win32.Service.ServiceStatus]$Status,
        [string]$MachineName,
        [int]$TimeoutSec = [int]::MaxValue
    )

    try {
        if (Test-Win32Service -Name $Name -MachineName $MachineName -Status $Status) {
            return $true
        }

        if ($TimeoutSec -le 0) {
            return $false
        }

        $timeout_ms = $TimeoutSec * 1000
        while ($timeout_ms -gt 0) {
            $service = Get-Win32Service -Name $Name -MachineName $MachineName
            if ($service.Status -eq $Status) {
                return $true
            }

            Start-Sleep -Milliseconds 250
            $timeout_ms -= 250
        }
    } catch {
        Write-Error $_
    }
    return $false
}

<#
.SYNOPSIS
Get the configuration for a service or all services.
.DESCRIPTION
This cmdlet gets the configuration for a service or all services.
.PARAMETER Name
Specify the name of the service.
.PARAMETER ServiceType
Specify the types of services to return when querying all services. Defaults to all user services.
.PARAMETER MachineName
Specify the target computer.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Service.ServiceConfig[]
#>
function Get-Win32ServiceConfig {
    [CmdletBinding(DefaultParameterSetName="All")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName="FromName")]
        [string]$Name,
        [parameter(ParameterSetName = "All")]
        [NtCoreLib.Win32.Service.ServiceType]$ServiceType = [NtCoreLib.Win32.Service.ServiceUtils]::GetServiceTypes(),
        [string]$MachineName
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromName" {
            [NtCoreLib.Win32.Service.ServiceUtils]::GetServiceConfiguration($MachineName, $Name)
        }
        "All" {
            [NtCoreLib.Win32.Service.ServiceUtils]::GetServiceConfiguration($MachineName, $ServiceType) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get the configuration for a service or all services.
.DESCRIPTION
This cmdlet gets the configuration for a service or all services.
.PARAMETER Name
Specify the name of the service.
.PARAMETER ServiceType
Specify the types of services to return when querying all services. Defaults to all user services.
.PARAMETER MachineName
Specify the target computer.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Service.ServiceConfig[]
#>
function Get-Win32ServiceConfig {
    [CmdletBinding(DefaultParameterSetName="All")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName="FromName")]
        [string]$Name,
        [parameter(ParameterSetName = "All")]
        [NtCoreLib.Win32.Service.ServiceType]$ServiceType = [NtCoreLib.Win32.Service.ServiceUtils]::GetServiceTypes(),
        [string]$MachineName
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromName" {
            [NtCoreLib.Win32.Service.ServiceUtils]::GetServiceConfiguration($MachineName, $Name)
        }
        "All" {
            [NtCoreLib.Win32.Service.ServiceUtils]::GetServiceConfiguration($MachineName, $ServiceType) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get the service triggers for a service.
.DESCRIPTION
This cmdlet gets the service triggers for a service.
.PARAMETER Name
The name of the service.
.PARAMETER MachineName
Specify the target computer.
.PARAMETER Action
Specify an action to filter on.
.PARAMETER Service
Specify a service object.
.INPUTS
NtCoreLib.Win32.Service.ServiceInstance[]
.OUTPUTS
NtCoreLib.Win32.Service.Triggers.ServiceTriggerInformation[]
.EXAMPLE
Get-Win32ServiceTrigger -Name "WebClient"
Get the service triggers for the WebClient service.
#>
function Get-Win32ServiceTrigger { 
    [CmdletBinding(DefaultParameterSetName="FromName")]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromName")]
        [string]$Name,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromService", ValueFromPipeline)]
        [NtCoreLib.Win32.Service.ServiceInstance]$Service,
        [NtCoreLib.Win32.Service.Triggers.ServiceTriggerAction]$Action = 0,
        [string]$MachineName
    )

    PROCESS {
        if ($PSCmdlet.ParameterSetName -eq "FromName") {
            $service = Get-Win32Service -MachineName $MachineName -Name $Name
        }
        if ($null -ne $service) {
            $triggers = $service.Triggers
            if ($Action -ne 0) {
                $triggers = $triggers | Where-Object Action -eq $Action
            }
            $triggers | Write-Output
        }
    }
}

<#
.SYNOPSIS
Gets a list of win32 services.
.DESCRIPTION
This cmdlet gets a list of all win32 services. 
.PARAMETER State
Specify the state of the services to get.
.PARAMETER Type
Specify to filter the services to specific types only.
.PARAMETER Name
Specify names to lookup.
.PARAMETER MachineName
Specify the target computer.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Service.ServiceInstance[]
.EXAMPLE
Get-Win32Service
Get all services.
.EXAMPLE
Get-Win32Service -State Active
Get all active services.
.EXAMPLE
Get-Win32Service -State All -Type UserService
Get all user services.
.EXAMPLE
Get-Win32Service -ProcessId 1234
Get services running in PID 1234.
.EXAMPLE
Get-Win32Service -Name WebClient
Get the WebClient service.
#>
function Get-Win32Service {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(ParameterSetName = "All")]
        [NtCoreLib.Win32.Service.ServiceState]$State = "All",
        [parameter(ParameterSetName = "All")]
        [NtCoreLib.Win32.Service.ServiceType]$Type = 0,
        [parameter(Mandatory, ParameterSetName = "FromName", Position = 0)]
        [string[]]$Name,
        [parameter(Mandatory, ParameterSetName = "FromPid", Position = 0)]
        [int[]]$ProcessId,
        [string]$MachineName
    )

    PROCESS {
        switch ($PSCmdlet.ParameterSetName) {
            "All" {
                if ($Type -eq 0) {
                    $Type = [NtCoreLib.Win32.Service.ServiceUtils]::GetServiceTypes()
                }
                [NtCoreLib.Win32.Service.ServiceUtils]::GetServices($MachineName, $State, $Type) | Write-Output
            }
            "FromName" {
                foreach ($n in $Name) {
                    [NtCoreLib.Win32.Service.ServiceUtils]::GetService($MachineName, $n) | Write-Output
                }
            }
            "FromPid" {
                Get-Win32Service -State Active -MachineName $MachineName | Where-Object {$_.ProcessId -in $ProcessId}
            }
        }
    }
}
