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
Create a new Win32 process configuration.
.DESCRIPTION
This cmdlet creates a new Win32 process configuration which you can then pass to New-Win32Process.
.PARAMETER CommandLine
The command line of the process to create.
.PARAMETER ApplicationName
Optional path to the application executable.
.PARAMETER ProcessSecurityDescriptor
Optional security descriptor for the process.
.PARAMETER ThreadSecurityDescriptor
Optional security descriptor for the initial thread.
.PARAMETER ParentProcess
Optional process to act as the parent, needs CreateProcess access to succeed.
.PARAMETER CreationFlags
Flags to affect process creation.
.PARAMETER TerminateOnDispose
Specify switch to terminate the process when the Win32Process object is disposed.
.PARAMETER Environment
Optional environment block for the new process.
.PARAMETER CurrentDirectory
Optional current directory for the new process.
.PARAMETER Desktop
Optional desktop for the new process.
.PARAMETER Title
Optional title for the new process.
.PARAMETER InheritHandles
Switch to specify whether to inherit handles into new process.
.PARAMETER InheritProcessHandle
Switch to specify whether the process handle is inheritable
.PARAMETER InheritThreadHandle
Switch to specify whether the thread handle is inheritable.
.PARAMETER MitigationOptions
Specify optional mitigation options.
.PARAMETER Win32kFilterFlags
Specify filter flags for Win32k filter
.PARAMETER Win32kFilterLevel
Specify the filter level for the Win32k filter.
.PARAMETER Token
Specify a token to start the process with.
.PARAMETER ProtectionLevel
Specify the protection level when creating a protected process.
.PARAMETER DebugObject
Specify a debug object to run the process under. You need to also specify DebugProcess or DebugOnlyThisProcess flags as well.
.PARAMETER NoTokenFallback
Specify to not fallback to using CreateProcessWithToken if CreateProcessAsUser fails.
.PARAMETER AppContainerProfile
Specify an app container profile to use.
.PARAMETER ExtendedFlags
 Specify extended creation flags.
.PARAMETER JobList
 Specify list of jobs to assign the process to.
.PARAMETER Credential
Specify user credentials for CreateProcessWithLogon.
.PARAMETER LogonFlags
Specify logon flags for CreateProcessWithLogon.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Win32ProcessConfig
#>
function New-Win32ProcessConfig {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$CommandLine,
        [string]$ApplicationName,
        [NtApiDotNet.SecurityDescriptor]$ProcessSecurityDescriptor,
        [NtApiDotNet.SecurityDescriptor]$ThreadSecurityDescriptor,
        [NtApiDotNet.NtProcess]$ParentProcess,
        [NtApiDotNet.Win32.CreateProcessFlags]$CreationFlags = 0,
        [NtApiDotNet.Win32.ProcessMitigationOptions]$MitigationOptions = 0,
        [switch]$TerminateOnDispose,
        [byte[]]$Environment,
        [string]$CurrentDirectory,
        [string]$Desktop,
        [string]$Title,
        [switch]$InheritHandles,
        [switch]$InheritProcessHandle,
        [switch]$InheritThreadHandle,
        [NtApiDotNet.Win32.Win32kFilterFlags]$Win32kFilterFlags = 0,
        [int]$Win32kFilterLevel = 0,
        [NtApiDotNet.NtToken]$Token,
        [NtApiDotNet.Win32.ProtectionLevel]$ProtectionLevel = "WindowsPPL",
        [NtApiDotNet.NtDebug]$DebugObject,
        [switch]$NoTokenFallback,
        [NtApiDotNet.Win32.AppContainerProfile]$AppContainerProfile,
        [NtApiDotNet.Win32.ProcessExtendedFlags]$ExtendedFlags = 0,
        [NtApiDotNet.ChildProcessMitigationFlags]$ChildProcessMitigations = 0,
        [NtApiDotNet.NtJob[]]$JobList,
        [NtApiDotNet.Win32.Security.Authentication.UserCredentials]$Credential,
        [NtApiDotNet.Win32.CreateProcessLogonFlags]$LogonFlags = 0
    )
    $config = New-Object NtApiDotNet.Win32.Win32ProcessConfig
    $config.CommandLine = $CommandLine
    if (-not [string]::IsNullOrEmpty($ApplicationName)) {
        $config.ApplicationName = $ApplicationName
    }
    $config.ProcessSecurityDescriptor = $ProcessSecurityDescriptor
    $config.ThreadSecurityDescriptor = $ThreadSecurityDescriptor
    $config.ParentProcess = $ParentProcess
    $config.CreationFlags = $CreationFlags
    $config.TerminateOnDispose = $TerminateOnDispose
    $config.Environment = $Environment
    if (-not [string]::IsNullOrEmpty($Desktop)) {
        $config.Desktop = $Desktop
    }
    if (-not [string]::IsNullOrEmpty($CurrentDirectory)) {
        $config.CurrentDirectory = $CurrentDirectory
    }
    if (-not [string]::IsNullOrEmpty($Title)) {
        $config.Title = $Title
    }
    $config.InheritHandles = $InheritHandles
    $config.InheritProcessHandle = $InheritProcessHandle
    $config.InheritThreadHandle = $InheritThreadHandle
    $config.MitigationOptions = $MitigationOptions
    $config.Win32kFilterFlags = $Win32kFilterFlags
    $config.Win32kFilterLevel = $Win32kFilterLevel
    $config.Token = $Token
    $config.ProtectionLevel = $ProtectionLevel
    $config.DebugObject = $DebugObject
    $config.NoTokenFallback = $NoTokenFallback
    if ($AppContainerProfile -ne $null) {
        $config.AppContainerSid = $AppContainerProfile.Sid
        $config.Capabilities.AddRange($AppContainerProfile.Capabilities)
    }
    $config.ExtendedFlags = $ExtendedFlags
    $config.ChildProcessMitigations = $ChildProcessMitigations
    if ($null -ne $JobList) {
        $config.JobList.AddRange($JobList)
    }
    $config.Credentials = $Credential
    $config.LogonFlags = $LogonFlags
    return $config
}

<#
.SYNOPSIS
Create a new Win32 process.
.DESCRIPTION
This cmdlet creates a new Win32 process with an optional security descriptor.
.PARAMETER CommandLine
The command line of the process to create.
.PARAMETER ApplicationName
Optional path to the application executable.
.PARAMETER ProcessSecurityDescriptor
Optional security descriptor for the process.
.PARAMETER ThreadSecurityDescriptor
Optional security descriptor for the initial thread.
.PARAMETER ParentProcess
Optional process to act as the parent, needs CreateProcess access to succeed.
.PARAMETER CreationFlags
Flags to affect process creation.
.PARAMETER TerminateOnDispose
Specify switch to terminate the process when the Win32Process object is disposed.
.PARAMETER Environment
Optional environment block for the new process.
.PARAMETER CurrentDirectory
Optional current directory for the new process.
.PARAMETER Desktop
Optional desktop for the new process.
.PARAMETER Title
Optional title for the new process.
.PARAMETER InheritHandles
Switch to specify whether to inherit handles into new process.
.PARAMETER InheritProcessHandle
Switch to specify whether the process handle is inheritable
.PARAMETER InheritThreadHandle
Switch to specify whether the thread handle is inheritable.
.PARAMETER MitigationOptions
Specify optional mitigation options.
.PARAMETER ProtectionLevel
Specify the protection level when creating a protected process.
.PARAMETER DebugObject
Specify a debug object to run the process under. You need to also specify DebugProcess or DebugOnlyThisProcess flags as well.
.PARAMETER NoTokenFallback
Specify to not fallback to using CreateProcessWithLogon if CreateProcessAsUser fails.
.PARAMETER Token
Specify an explicit token to create the new process with.
.PARAMETER ExtendedFlags
 Specify extended creation flags.
.PARAMETER JobList
 Specify list of jobs to assign the process to.
.PARAMETER Config
Specify the configuration for the new process.
.PARAMETER Wait
Specify to wait for the process to exit.
.PARAMETER WaitTimeout
Specify the timeout to wait for the process to exit. Defaults to infinite.
.PARAMETER Credential
Specify user credentials for CreateProcessWithLogon.
.PARAMETER LogonFlags
Specify logon flags for CreateProcessWithLogon.
.PARAMETER Close
Specify to close the process and thread handles and not return anything.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Win32Process
#>
function New-Win32Process {
    [CmdletBinding(DefaultParameterSetName = "FromArgs")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromArgs")]
        [string]$CommandLine,
        [Parameter(ParameterSetName = "FromArgs")]
        [string]$ApplicationName,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtApiDotNet.SecurityDescriptor]$ProcessSecurityDescriptor,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtApiDotNet.SecurityDescriptor]$ThreadSecurityDescriptor,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtApiDotNet.NtProcess]$ParentProcess,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtApiDotNet.Win32.CreateProcessFlags]$CreationFlags = 0,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtApiDotNet.Win32.ProcessMitigationOptions]$MitigationOptions = 0,
        [Parameter(ParameterSetName = "FromArgs")]
        [switch]$TerminateOnDispose,
        [Parameter(ParameterSetName = "FromArgs")]
        [byte[]]$Environment,
        [Parameter(ParameterSetName = "FromArgs")]
        [string]$CurrentDirectory,
        [Parameter(ParameterSetName = "FromArgs")]
        [string]$Desktop,
        [Parameter(ParameterSetName = "FromArgs")]
        [string]$Title,
        [Parameter(ParameterSetName = "FromArgs")]
        [switch]$InheritHandles,
        [Parameter(ParameterSetName = "FromArgs")]
        [switch]$InheritProcessHandle,
        [Parameter(ParameterSetName = "FromArgs")]
        [switch]$InheritThreadHandle,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtApiDotNet.NtToken]$Token,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtApiDotNet.Win32.ProtectionLevel]$ProtectionLevel = "WindowsPPL",
        [Parameter(ParameterSetName = "FromArgs")]
        [NtApiDotNet.NtDebug]$DebugObject,
        [Parameter(ParameterSetName = "FromArgs")]
        [switch]$NoTokenFallback,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtApiDotNet.Win32.AppContainerProfile]$AppContainerProfile,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtApiDotNet.Win32.ProcessExtendedFlags]$ExtendedFlags = 0,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtApiDotNet.ChildProcessMitigationFlags]$ChildProcessMitigations = 0,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtApiDotNet.NtJob[]]$JobList,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtApiDotNet.Win32.Security.Authentication.UserCredentials]$Credential,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtApiDotNet.Win32.CreateProcessLogonFlags]$LogonFlags = 0,
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromConfig")]
        [NtApiDotNet.Win32.Win32ProcessConfig]$Config,
        [switch]$Wait,
        [NtApiDotNet.NtWaitTimeout]$WaitTimeout = [NtApiDotNet.NtWaitTimeout]::Infinite,
        [switch]$Close
    )

    if ($null -eq $Config) {
        $Config = New-Win32ProcessConfig $CommandLine -ApplicationName $ApplicationName `
            -ProcessSecurityDescriptor $ProcessSecurityDescriptor -ThreadSecurityDescriptor $ThreadSecurityDescriptor `
            -ParentProcess $ParentProcess -CreationFlags $CreationFlags -TerminateOnDispose:$TerminateOnDispose `
            -Environment $Environment -CurrentDirectory $CurrentDirectory -Desktop $Desktop -Title $Title `
            -InheritHandles:$InheritHandles -InheritProcessHandle:$InheritProcessHandle -InheritThreadHandle:$InheritThreadHandle `
            -MitigationOptions $MitigationOptions -Token $Token -ProtectionLevel $ProtectionLevel -NoTokenFallback:$NoTokenFallback `
            -DebugObject $DebugObject -AppContainerProfile $AppContainerProfile -ExtendedFlags $ExtendedFlags `
            -ChildProcessMitigations $ChildProcessMitigations -JobList $JobList -Credential $Credential -LogonFlags $LogonFlags
    }

    $p = [NtApiDotNet.Win32.Win32Process]::CreateProcess($config)
    if ($Wait) {
        $p.Process.Wait($WaitTimeout)
    }
    if ($Close) {
        $p.Dispose()
    } else {
        $p | Write-Output
    }
}

function Test-ProcessToken {
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtApiDotNet.NtProcess]$Process,
        [parameter(Mandatory, Position = 1)]
        [NtApiDotNet.Sid]$User,
        [NtApiDotNet.TokenPrivilegeValue[]]$RequiredPrivilege,
        [NtApiDotNet.Sid[]]$RequiredGroup
    )
    Use-NtObject($token = Get-NtToken -Primary -Process $Process -Access Query -ErrorAction SilentlyContinue) {
        if ($null -eq $token) {
            return $false
        }

        if ($token.User.Sid -ne $User) {
            return $false
        }
        $privs = $token.Privileges.Name
        foreach ($priv in $RequiredPrivilege) {
            if ($priv.ToString() -notin $privs) {
                return $false
            }
        }

        $groups = $token.Groups | Where-Object Enabled
        foreach ($group in $RequiredGroup) {
            if ($group -notin $groups.Sid) {
                return $false
            }
        }
    }
    return $true
}

<#
.SYNOPSIS
Starts a new Win32 process which is a child of a process meeting a set of criteria.
.DESCRIPTION
This cmdlet starts a new Win32 process which is a child of a process meeting a set of criteria such as user account, privileges and groups. You can use this as an admin to get a system process spawned on the current desktop.
.PARAMETER CommandLine
The command line of the process to create.
.PARAMETER CreationFlags
Flags to affect process creation.
.PARAMETER TerminateOnDispose
Specify switch to terminate the process when the Win32Process object is disposed.
.PARAMETER Desktop
Optional desktop for the new process.
.PARAMETER RequiredPrivilege
Optional list of privileges the parent process must have to create the child.
.PARAMETER RequiredGroup
Optional list of groups the parent process must have to create the child.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Win32Process
.EXAMPLE
Start-Win32ChildProcess cmd.exe
Start a new child process as the system user.
.EXAMPLE
Start-Win32ChildProcess cmd.exe -User LS
Start a new child process as the local service user.
.EXAMPLE
Start-Win32ChildProcess cmd.exe -RequiredPrivilege SeAssignPrimaryTokenPrivilege
Start a new child process as the system user with SeAssignPrimaryTokenPrivilege.
.EXAMPLE
Start-Win32ChildProcess cmd.exe -RequiredGroup BA
Start a new child process as the system user with the builtin administrators group.
#>
function Start-Win32ChildProcess {
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$CommandLine,
        [NtApiDotNet.Sid]$User = "SY",
        [NtApiDotNet.TokenPrivilegeValue[]]$RequiredPrivilege,
        [NtApiDotNet.Sid[]]$RequiredGroup,
        [string]$Desktop = "WinSta0\Default",
        [NtApiDotNet.Win32.CreateProcessFlags]$CreationFlags = "NewConsole",
        [switch]$TerminateOnDispose,
        [switch]$PassThru
    )

    Set-NtTokenPrivilege SeDebugPrivilege | Out-Null

    Use-NtObject($ps = Get-NtProcess -Access QueryLimitedInformation, CreateProcess `
            -FilterScript { Test-ProcessToken $_ -User $User -RequiredPrivilege $RequiredPrivilege -RequiredGroup $RequiredGroup }) {
        $parent = $ps | Select-Object -First 1
        if ($null -eq $parent) {
            Write-Error "Couldn't find suitable process to spawn a child."
            return
        }
        New-Win32Process -CommandLine $CommandLine -Desktop $Desktop -CreationFlags $CreationFlags -ParentProcess $parent -TerminateOnDispose:$TerminateOnDispose
    }
}
