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
Get registered WNF subscription.
.DESCRIPTION
This cmdlet gets the registered WNF entries or a specific entry from a state name.
.PARAMETER StateName
The statename to get.
.PARAMETER DontCheckExists
Specify to not check that the WNF entry exists.
.PARAMETER Name
Lookup the state name from a well known text name.
.OUTPUTS
NtCoreLib.NtWnf
.EXAMPLE
Get-NtWnf
Get all registered WNF entries.
.EXAMPLE
Get-NtWnf 0x12345678
Get a WNF entry from a state name.
.EXAMPLE
Get-NtWnf 0x12345678 -DontCheckExists
Get a WNF entry from a state name but don't check if it exists.
.EXAMPLE
Get-NtWnf "WNF_AOW_BOOT_PROGRESS"
Get a WNF entry from a name.
#>
function Get-NtWnf {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Position = 0, Mandatory, ParameterSetName = "StateName")]
        [uint64]$StateName,
        [parameter(ParameterSetName = "StateName")]
        [parameter(ParameterSetName = "Name")]
        [switch]$DontCheckExists,
        [parameter(Position = 0, Mandatory, ParameterSetName = "Name")]
        [string]$Name
    )
    switch ($PSCmdlet.ParameterSetName) {
        "All" {
            [NtCoreLib.NtWnf]::GetRegisteredNotifications()
        }
        "StateName" {
            [NtCoreLib.NtWnf]::Open($StateName, -not $DontCheckExists)
        }
        "Name" {
            [NtCoreLib.NtWnf]::Open($Name, -not $DontCheckExists)
        }
    }
}

<#
.SYNOPSIS
Open a file using the Win32 CreateFile API.
.DESCRIPTION
This cmdlet opens a file using the Win32 CreateFile API rather than the native APIs.
.PARAMETER Path
Specify the path to open. Note that the function doesn't resolve relative paths from the PS working directory.
.PARAMETER DesiredAccess
Specify the desired access for the handle.
.PARAMETER ShareMode
Specify the share mode for the file.
.PARAMETER SecurityDescriptor
Specify an optional security descriptor.
.PARAMETER InheritHandle
Specify that the file handle should be inheritable.
.PARAMETER Disposition
Specify the file open disposition.
.PARAMETER FlagsAndAttributes
Specify flags and attributes for the open.
.PARAMETER TemplateFile
Specify a template file to copy certain properties from.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtFile
.EXAMPLE
Get-Win32File -Path c:\abc\xyz.txt
Open the existing file c:\abc\xyz.txt
#>
function Get-Win32File {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$Path,
        [NtCoreLib.FileAccessRights]$DesiredAccess = "MaximumAllowed",
        [NtCoreLib.FileShareMode]$ShareMode = 0,
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [switch]$InheritHandle,
        [NtCoreLib.Win32.IO.CreateFileDisposition]$Disposition = "OpenExisting",
        [NtCoreLib.Win32.IO.CreateFileFlagsAndAttributes]$FlagsAndAttributes = 0,
        [NtCoreLib.NtFile]$TemplateFile
    )

    [NtCoreLib.Win32.IO.Win32FileUtils]::CreateFile($Path, $DesiredAccess, $ShareMode, `
            $SecurityDescriptor, $InheritHandle, $Disposition, $FlagsAndAttributes, $TemplateFile)
}

<#
.SYNOPSIS
Start an accessible scheduled task.
.DESCRIPTION
This cmdlet starts a scheduled task based on an accessible task result.
.PARAMETER Task
Specify the task to start.
.PARAMETER User
Specify the user to run the task under. Can be a username or a SID.
.PARAMETER Flags
Specify optional flags.
.PARAMETER SessionId
Specify an optional session ID.
.PARAMETER Arguments
Specify optional arguments to the pass to the task.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Start-AccessibleScheduledTask -Task $task
Start a task with no options.
.EXAMPLE
Start-AccessibleScheduledTask -Task $task -Arguments "A", B"
Start a task with optional argument strings "A" and "B"
#>
function Start-AccessibleScheduledTask {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtObjectManager.Cmdlets.Accessible.ScheduledTaskAccessCheckResult]$Task,
        [string]$User,
        [NtObjectManager.Utils.ScheduledTask.TaskRunFlags]$Flags = 0,
        [int]$SessionId,
        [string[]]$Arguments
    )

    $Task.RunEx($Flags, $SessionId, $User, $Arguments)
}

<#
.SYNOPSIS
Gets entries from an object directory.
.DESCRIPTION
This cmdlet gets the list entries in an object directory.
.PARAMETER Directory
Specify the directory.
.INPUTS
None
.OUTPUTS
NtCoreLib.ObjectDirectoryInformation[]
.EXAMPLE
Get-NtDirectoryEntry $dir
Get list of entries from $dir.
#>
function Get-NtDirectoryEntry {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.NtDirectory]$Directory
    )

    $Directory.Query() | Write-Output
}

<#
.SYNOPSIS
Terminates a job object.
.DESCRIPTION
This cmdlet terminates a job object and all it's processes.
.PARAMETER Job
Specify a Job object to terminate.
.PARAMETER Status
Specify the NT status code to terminate with.
.INPUTS
None
.OUTPUTS
Bool
.EXAMPLE
Stop-NtJob -Job $job
Terminate a job with STATUS_SUCCESS code.
.EXAMPLE
Stop-NtJob -Job $job -Status STATUS_ACCESS_DENIED
Terminate a job with STATUS_ACCESS_DENIED code.
#>
function Stop-NtJob {
    param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.NtJob]$Job,
        [parameter(Position = 1)]
        [NtCoreLib.NtStatus]$Status = 0
    )
    $Job.Terminate($Status)
}

<#
.SYNOPSIS
Call a method in an enclave.
.DESCRIPTION
This cmdlet calls a method in an enclave.
.PARAMETER Routine
Specify the enclave routine to call.
.PARAMETER Parameter
Specify parameter to pass to the routine.
.PARAMETER WaitForThread
Specify to wait for an idle thread before calling.
.INPUTS
None
.OUTPUTS
int64
#>
function Invoke-NtEnclave {
    param(
        [Parameter(Position = 0, Mandatory)]
        [int64]$Routine,
        [int64]$Parameter = 0,
        [switch]$WaitForThread
    )

    [NtCoreLib.NtEnclave]::Call($Routine, $Parameter, $WaitForThread)
}

<#
.SYNOPSIS
Create a new memory buffer.
.DESCRIPTION
This cmdlet creates a new memory buffer object of a certain size.
.PARAMETER Length
Specify the length in bytes of the buffer.
.INPUTS
None
.OUTPUTS
NtCoreLib.Native.SafeBuffers.SafeHGlobalBuffer
#>
function New-Win32MemoryBuffer {
    param(
        [Parameter(Position = 0, Mandatory)]
        [int]$Length
    )

    [NtCoreLib.Native.SafeBuffers.SafeHGlobalBuffer]::new($Length)
}