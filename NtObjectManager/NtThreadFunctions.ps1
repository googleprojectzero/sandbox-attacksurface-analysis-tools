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
Suspend a thread.
.DESCRIPTION
This cmdlet suspends a thread.
.PARAMETER Process
The thread to suspend.
.INPUTS
NtCoreLib.NtThread
.OUTPUTS
None
#>
function Suspend-NtThread {
    [CmdletBinding(DefaultParameterSetName = "FromThread")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromThread", ValueFromPipeline)]
        [NtCoreLib.NtThread[]]$Thread
    )

    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "FromThread" {
                foreach ($t in $Thread) {
                    $t.Suspend() | Out-Null
                }
            }
        }
    }
}

<#
.SYNOPSIS
Resume a thread.
.DESCRIPTION
This cmdlet resumes a thread.
.PARAMETER Process
The thread to resume.
.INPUTS
NtCoreLib.NtThread
.OUTPUTS
None
#>
function Resume-NtThread {
    [CmdletBinding(DefaultParameterSetName = "FromThread")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromThread", ValueFromPipeline)]
        [NtCoreLib.NtThread[]]$Thread
    )

    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "FromThread" {
                foreach ($t in $Thread) {
                    $t.Resume() | Out-Null
                }
            }
        }
    }
}

<#
.SYNOPSIS
Stop a thread.
.DESCRIPTION
This cmdlet stops/kills a thread with an optional status code.
.PARAMETER Process
The thread to stop.
.INPUTS
NtCoreLib.NtThread
.OUTPUTS
None
#>
function Stop-NtThread {
    [CmdletBinding(DefaultParameterSetName = "FromThread")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromThread", ValueFromPipeline)]
        [NtCoreLib.NtThread[]]$Thread,
        [NtCoreLib.NtStatus]$ExitCode = 0
    )

    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "FromThread" {
                foreach ($t in $Thread) {
                    $t.Terminate($ExitCode)
                }
            }
        }
    }
}

<#
.SYNOPSIS
Query the context for a thread.
.DESCRIPTION
This cmdlet queries the context for a thread.
.PARAMETER Thread
Specify the thread to get the context for.
.PARAMETER ContextFlags
Specify the parts of the context to query.
.INPUTS
None
.OUTPUTS
NtCoreLib.IContext
.EXAMPLE
Get-NtThreadContext -Thread $thread
Query the thread's context for all state.
#>
function Get-NtThreadContext {
    param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtThread]$Thread,
        [NtCoreLib.ContextFlags]$ContextFlags = "All"
    )
    $Thread.GetContext($ContextFlags)
}

<#
.SYNOPSIS
Set the context for a thread.
.DESCRIPTION
This cmdlet sets the context for a thread.
.PARAMETER Thread
Specify the thread to set the context for.
.PARAMETER Context
Specify the context to set. You must configure the ContextFlags to determine what parts to set.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-NtThreadContext -Thread $thread -Context $context
Sets the thread's context.
#>
function Set-NtThreadContext {
    param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtThread]$Thread,
        [parameter(Mandatory, Position = 1)]
        [NtCoreLib.IContext]$Context
    )
    $Thread.SetContext($Context)
}

<#
.SYNOPSIS
Gets a work-on-behalf ticket for a thread.
.DESCRIPTION
This cmdlet gets the work-on-behalf ticket for a thread. 
.PARAMETER Thread
Specify a thread to get the ticket from.
.INPUTS
None
.OUTPUTS
NtCoreLib.WorkOnBehalfTicket
.EXAMPLE
Get-NtThreadWorkOnBehalfTicket
Get the work-on-behalf ticket for the current thread.
.EXAMPLE
Get-NtThreadWorkOnBehalfTicket -Thread $thread
Get the work-on-behalf ticket for a thread.
#>
function Get-NtThreadWorkOnBehalfTicket {
    param(
        [parameter(Position = 0)]
        [NtCoreLib.NtThread]$Thread
    )
    if ($Thread -eq $null) {
        [NtCoreLib.NtThread]::WorkOnBehalfTicket
    } else {
        $Thread.GetWorkOnBehalfTicket()
    }
}

<#
.SYNOPSIS
Set a work-on-behalf ticket on the current thread.
.DESCRIPTION
This cmdlet gets the work-on-behalf ticket for a thread. 
.PARAMETER Ticket
Specify the ticket to set.
.PARAMETER ThreadId
Specify the thread ID to set.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-NtThreadWorkOnBehalfTicket -Ticket $ticket
Set the work-on-behalf ticket for the current thread.
#>
function Set-NtThreadWorkOnBehalfTicket {
    [CmdletBinding(DefaultParameterSetName = "FromTicket")]
    param(
        [parameter(Mandatory, Position = 0, ParameterSetName="FromTicket")]
        [NtCoreLib.WorkOnBehalfTicket]$Ticket,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromThreadId")]
        [alias("tid")]
        [int]$ThreadId
    )
    if ($PSCmdlet.ParameterSetName -eq 'FromThreadId') {
        [NtCoreLib.NtThread]::SetWorkOnBehalfTicket($ThreadId)
    } else {
        [NtCoreLib.NtThread]::WorkOnBehalfTicket = $Ticket
    }
}

<#
.SYNOPSIS
Clear the work-on-behalf ticket on the current thread.
.DESCRIPTION
This cmdlet clears the work-on-behalf ticket for a thread. 
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Clear-NtThreadWorkOnBehalfTicket
Clear the work-on-behalf ticket for the current thread.
#>
function Clear-NtThreadWorkOnBehalfTicket {
    $ticket = [NtCoreLib.WorkOnBehalfTicket]::new(0)
    [NtCoreLib.NtThread]::WorkOnBehalfTicket = $ticket
}

<#
.SYNOPSIS
Gets the container ID for the current thread.
.DESCRIPTION
This cmdlet gets the container ID for the current thread thread.
.INPUTS
None
.OUTPUTS
Guid
.EXAMPLE
Get-NtThreadContainerId
Get the container ID for the current thread.
#>
function Get-NtThreadContainerId {
    [NtCoreLib.NtThread]::Current.ContainerId
}

<#
.SYNOPSIS
Attaches a container to impersonate the current thread.
.DESCRIPTION
This cmdlet attaches a container for impersonation on the current thread.
.PARAMETER Job
The job silo to set as the thread's container.
.INPUTS
None
.OUTPUTS
NtCoreLib.Utilities.Token.ThreadImpersonationContext
.EXAMPLE
$imp = Set-NtThreadContainer -Job $job
Sets the container for the current thread.
#>
function Set-NtThreadContainer {
    param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtJob]$Job
    )
    [NtCoreLib.NtThread]::AttachContainer($Job)
}
