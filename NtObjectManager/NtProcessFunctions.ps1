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
Create a new native NT process configuration.
.DESCRIPTION
This cmdlet creates a new native process configuration which you can then pass to New-NtProcess.
.PARAMETER ImagePath
The path to image file to load.
.PARAMETER CommandLine
The command line of the process to create.
.PARAMETER ProcessFlags
Flags to affect process creation.
.PARAMETER ThreadFlags
Flags to affect thread creation.
.PARAMETER ProtectedType
Protected process type.
.PARAMETER ProtectedSigner
Protected process signer.
.PARAMETER TerminateOnDispose
Specify switch to terminate the process when the CreateUserProcessResult object is disposed.
.PARAMETER ProhibitedImageCharacteristics
Specify prohibited image characteristics for the new process.
.PARAMETER ChildProcessMitigations
Specify child process mitigations.
.PARAMETER AdditionalFileAccess
Specify additional file access mask.
.PARAMETER InitFlags
Specify additional initialization flags.
.PARAMETER Win32Path
Specify ImagePath is a Win32 path.
.PARAMETER CaptureAdditionalInformation
Specify to capture additional information from create call.
.PARAMETER Secure
Specify to create a secure process.
.INPUTS
None
.OUTPUTS
NtApiDotNet.NtProcessCreateConfig
#>
function New-NtProcessConfig {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$ImagePath,
        [Parameter(Position = 1)]
        [string]$CommandLine,
        [NtApiDotNet.ProcessCreateFlags]$ProcessFlags = 0,
        [NtApiDotNet.ThreadCreateFlags]$ThreadFlags = 0,
        [NtApiDotNet.PsProtectedType]$ProtectedType = 0,
        [NtApiDotNet.PsProtectedSigner]$ProtectedSigner = 0,
        [NtApiDotNet.ImageCharacteristics]$ProhibitedImageCharacteristics = 0,
        [NtApiDotNet.ChildProcessMitigationFlags]$ChildProcessMitigations = 0,
        [NtApiDotNet.FileAccessRights]$AdditionalFileAccess = 0,
        [NtApiDotNet.ProcessCreateInitFlag]$InitFlags = 0,
        [switch]$TerminateOnDispose,
        [switch]$Win32Path,
        [switch]$CaptureAdditionalInformation,
        [switch]$Secure,
        [NtApiDotNet.NtObject[]]$InheritHandle
    )

    if ($Win32Path) {
        $ImagePath = Get-NtFilePath $ImagePath -Resolve
    }

    if ("" -eq $CommandLine) {
        $CommandLine = $ImagePath
    }

    $config = New-Object NtApiDotNet.NtProcessCreateConfig
    $config.ImagePath = $ImagePath
    $config.ProcessFlags = $ProcessFlags
    $config.ThreadFlags = $ThreadFlags
    $config.CommandLine = $CommandLine
    $config.ProhibitedImageCharacteristics = $ProhibitedImageCharacteristics
    $config.ChildProcessMitigations = $ChildProcessMitigations
    $config.AdditionalFileAccess = $AdditionalFileAccess
    $config.InitFlags = $InitFlags
    $config.TerminateOnDispose = $TerminateOnDispose
    if ($ProtectedType -ne 0 -or $ProtectedSigner -ne 0) {
        $config.AddProtectionLevel($ProtectedType, $ProtectedSigner)
        $config.ProcessFlags = $ProcessFlags -bor "ProtectedProcess"
    }
    $config.CaptureAdditionalInformation = $CaptureAdditionalInformation
    $config.Secure = $Secure
    if ($null -ne $InheritHandle) {
        $config.InheritHandleList.AddRange($InheritHandle)
    }

    return $config
}

<#
.SYNOPSIS
Create a new native NT process.
.DESCRIPTION
This cmdlet creates a new native NT process. This can be via NtCreateUserProcess with a configuration
or NtCreateProcessEx without configuration.
.PARAMETER Config
The configuration for the new process from New-NtProcessConfig.
.PARAMETER ReturnOnError
Specify to always return a result even on error.
.PARAMETER SecurityDescriptor
Specify security descriptor for the process.
.PARAMETER Access
Specify the access to the process object.
.PARAMETER Parent
Specify the parent process. Default is current process.
.PARAMETER Flags
Specify creation flags.
.PARAMETER Section
Specify initial image section.
.PARAMETER DebugPort
Specify debug port.
.PARAMETER Token
Specify process token.
.INPUTS
None
.OUTPUTS
NtApiDotNet.NtProcessCreateResult
NtApiDotNet.NtProcess
#>
function New-NtProcess {
    [CmdletBinding(DefaultParameterSetName="FromCreateEx")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName="FromConfig")]
        [NtApiDotNet.NtProcessCreateConfig]$Config,
        [Parameter(ParameterSetName="FromConfig")]
        [switch]$ReturnOnError,
        [Parameter(ParameterSetName="FromCreateEx")]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(ParameterSetName="FromCreateEx")]
        [NtApiDotnet.ProcessAccessRights]$Access = "MaximumAllowed",
        [Parameter(ParameterSetName="FromCreateEx")]
        [NtApiDotNet.NtProcess]$Parent,
        [Parameter(ParameterSetName="FromCreateEx")]
        [NtApiDotNet.ProcessCreateFlags]$Flags = 0,
        [Parameter(ParameterSetName="FromCreateEx")]
        [NtApiDotNet.NtSection]$Section,
        [Parameter(ParameterSetName="FromCreateEx")]
        [NtApiDotNet.NtDebug]$DebugPort,
        [Parameter(ParameterSetName="FromCreateEx")]
        [NtApiDotNet.NtToken]$Token
    )

    if ($PSCmdlet.ParameterSetName -eq "FromConfig") {
        [NtApiDotNet.NtProcess]::Create($Config, !$ReturnOnError)
    } else {
        Use-NtObject($obja = New-NtObjectAttributes -SecurityDescriptor $SecurityDescriptor) {
            [NtApiDotNet.NtProcess]::Create($obja, $Access, $Parent, $Flags, $Section, $DebugPort, $Token)
        }
    }
}

<#
.SYNOPSIS
Get security mitigations and token security information for processes.
.DESCRIPTION
This cmdlet will get the mitigation policies for processes it can access. The default is to return mitigations for all accessible processes.
.PARAMETER Name
The name of the processes to get mitigations for.
.PARAMETER ProcessId
One or more process IDs to get mitigations for.
.PARAMETER PageFlags
Optional flags to control what additional pages to dump
.INPUTS
None
.EXAMPLE
Get-NtProcessMitigations
Get all accessible process mitigations.
.EXAMPLE
Get-NtProcessMitigations -Name MicrosoftEdgeCP.exe
Get process mitigations for Edge content processes.
.EXAMPLE
Get-NtProcessMitigations -ProcessId 1234, 4568
Get process mitigations for two processes by ID.
#>
function Get-NtProcessMitigations {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(ParameterSetName = "FromName", Position = 0, Mandatory)]
        [string]$Name,
        [parameter(ParameterSetName = "FromProcessId", Position = 0, Mandatory)]
        [int[]]$ProcessId,
        [parameter(ParameterSetName = "FromProcess")]
        [NtApiDotNet.NtProcess[]]$Process
    )
    Set-NtTokenPrivilege SeDebugPrivilege | Out-Null
    $ps = switch ($PSCmdlet.ParameterSetName) {
        "All" {
            Get-NtProcess -Access QueryInformation
        }
        "FromName" {
            Get-NtProcess -Name $Name
        }
        "FromProcessId" {
            foreach ($id in $ProcessId) {
                Get-NtProcess -ProcessId $id
            }
        }
        "FromProcess" {
            Copy-NtObject -Object $Process
        }
    }
    Use-NtObject($ps) {
        foreach ($p in $ps) {
            try {
                Write-Output $p.Mitigations
            }
            catch {
                Write-Error $_
            }
        }
    }
}

<#
.SYNOPSIS
Get a specified mitigation policy value for a process.
.DESCRIPTION
This cmdlet queries for a specific mitigation policy value from a process. The result is an enumeration or a raw value depending on the request.
.PARAMETER Process
Specify the process to query. Defaults to the current process.
.PARAMETER Policy
Specify the mitigation policy.
.PARAMETER AsRaw
Specify the query the policy as a raw integer.
.INPUTS
None
.OUTPUTS
An enumerated value or an integer.
.EXAMPLE
Get-NtProcessMitigationPolicy Signature
Query the signature mitigation policy for the current process.
.EXAMPLE
Get-NtProcessMitigationPolicy Signature -Process $p
Query the signature mitigation policy for a specified process.
.EXAMPLE
Get-NtProcessMitigationPolicy Signature -Process-AsRaw
Query the signature mitigation policy for the current process as a raw integer.
#>
function Get-NtProcessMitigationPolicy {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtApiDotNet.ProcessMitigationPolicy]$Policy,
        [parameter(ValueFromPipeline)]
        [NtApiDotNet.NtProcess]$Process,
        [switch]$AsRaw
    )

    PROCESS {
        if ($null -eq $Process) {
            $Process = Get-NtProcess -Current
        }
        if ($AsRaw) {
            $Process.GetRawMitigationPolicy($Policy) | Write-Output
        }
        else {
            $Process.GetMitigationPolicy($Policy) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Set a specified mitigation policy value for a process.
.DESCRIPTION
This cmdlet sets a specific mitigation policy value for a process. The policy value can either be an explicit enumeration or a raw value.
.PARAMETER Process
Specify the process to set. Defaults to the current process and the majority of policies can't be set externally.
.PARAMETER Policy
Specify the mitigation policy when setting a raw value.
.PARAMETER RawValue
Specify the raw value to set.
.PARAMETER ImageLoad,
Specify policy flags for image load mitigation.
.PARAMETER Signature,
Specify policy flags for signature mitigation policy.
.PARAMETER SystemCallDisable,
Specify policy flags for system call disable mitigation policy.
.PARAMETER DynamicCode,
Specify policy flags for dynamic code mitigation policy.
.PARAMETER ExtensionPointDisable,
Specify policy flags for extension point disable mitigation policy.
.PARAMETER FontDisable,
Specify policy flags for font disable mitigation policy.
.PARAMETER ControlFlowGuard,
Specify policy flags for control flow guard mitigation policy.
.PARAMETER StrictHandleCheck,
Specify policy flags for strict handle check mitigation policy.
.PARAMETER ChildProcess,
Specify policy flags for child process mitigation policy.
.PARAMETER PayloadRestriction,
Specify policy flags for payload restrictions mitigation policy.
.PARAMETER SystemCallFilter,
Specify policy flags for system call filter mitigation policy.
.PARAMETER SideChannelIsolation,
Specify policy flags for side channel isolation mitigation policy.
.PARAMETER Aslr
Specify policy flags for ASLR mitigation policy.
.PARAMETER RedirectionTrust
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-NtProcessMitigationPolicy -Policy Signature -RawValue 1
Set the signature mitigation policy for the current process with a raw value of 1.
.EXAMPLE
Set-NtProcessMitigationPolicy -Signature MicrosoftSignedOnly
Set mitigation signed only signature policy for the current process.
.EXAMPLE
Set-NtProcessMitigationPolicy -Signature MicrosoftSignedOnly -Process $p
Set mitigation signed only signature policy for a specified process.
#>
function Set-NtProcessMitigationPolicy {
    [CmdletBinding()]
    Param(
        [parameter(ValueFromPipeline)]
        [NtApiDotNet.NtProcess]$Process,
        [parameter(Mandatory, ParameterSetName = "FromRaw")]
        [int]$RawValue,
        [parameter(Mandatory, ParameterSetName = "FromRaw")]
        [NtApiDotNet.ProcessMitigationPolicy]$Policy,
        [parameter(Mandatory, ParameterSetName = "FromImageLoad")]
        [NtApiDotNet.ProcessMitigationImageLoadPolicy]$ImageLoad,
        [parameter(Mandatory, ParameterSetName = "FromSignature")]
        [NtApiDotNet.ProcessMitigationBinarySignaturePolicy]$Signature,
        [parameter(Mandatory, ParameterSetName = "FromSystemCallDisable")]
        [NtApiDotNet.ProcessMitigationSystemCallDisablePolicy]$SystemCallDisable,
        [parameter(Mandatory, ParameterSetName = "FromDynamicCode")]
        [NtApiDotNet.ProcessMitigationDynamicCodePolicy]$DynamicCode,
        [parameter(Mandatory, ParameterSetName = "FromExtensionPointDisable")]
        [NtApiDotNet.ProcessMitigationExtensionPointDisablePolicy]$ExtensionPointDisable,
        [parameter(Mandatory, ParameterSetName = "FromFontDisable")]
        [NtApiDotNet.ProcessMitigationFontDisablePolicy]$FontDisable,
        [parameter(Mandatory, ParameterSetName = "FromControlFlowGuard")]
        [NtApiDotNet.ProcessMitigationControlFlowGuardPolicy]$ControlFlowGuard,
        [parameter(Mandatory, ParameterSetName = "FromStrictHandleCheck")]
        [NtApiDotNet.ProcessMitigationStrictHandleCheckPolicy]$StrictHandleCheck,
        [parameter(Mandatory, ParameterSetName = "FromChildProcess")]
        [NtApiDotNet.ProcessMitigationChildProcessPolicy]$ChildProcess,
        [parameter(Mandatory, ParameterSetName = "FromPayloadRestriction")]
        [NtApiDotNet.ProcessMitigationPayloadRestrictionPolicy]$PayloadRestriction,
        [parameter(Mandatory, ParameterSetName = "FromSystemCallFilter")]
        [NtApiDotNet.ProcessMitigationSystemCallFilterPolicy]$SystemCallFilter,
        [parameter(Mandatory, ParameterSetName = "FromSideChannelIsolation")]
        [NtApiDotNet.ProcessMitigationSideChannelIsolationPolicy]$SideChannelIsolation,
        [parameter(Mandatory, ParameterSetName = "FromAslr")]
        [NtApiDotNet.ProcessMitigationAslrPolicy]$Aslr,
        [parameter(Mandatory, ParameterSetName = "FromRedirectionTrust")]
        [NtApiDotNet.ProcessMitigationRedirectionTrustPolicy]$RedirectionTrust
    )

    BEGIN {
        $Value = 0
        $FromRaw = $false
        switch ($PsCmdlet.ParameterSetName) {
            "FromRaw" { $Value = $RawValue; $FromRaw = $true }
            "FromImageLoad" { $Policy = "ImageLoad"; $Value = $ImageLoad }
            "FromSignature" { $Policy = "Signature"; $Value = $Signature }
            "FromSystemCallDisable" { $Policy = "SystemCallDisable"; $Value = $SystemCallDisable }
            "FromDynamicCode" { $Policy = "DynamicCode"; $Value = $DynamicCode }
            "FromExtensionPointDisable" { $Policy = "ExtensionPointDisable"; $Value = $ExtensionPointDisable }
            "FromFontDisable" { $Policy = "FontDisable"; $Value = $FontDisable }
            "FromControlFlowGuard" { $Policy = "ControlFlowGuard"; $Value = $ControlFlowGuard }
            "FromStrictHandleCheck" { $Policy = "StrictHandleCheck"; $Value = $StrictHandleCheck }
            "FromChildProcess" { $Policy = "ChildProcess"; $Value = $ChildProcess }
            "FromPayloadRestriction" { $Policy = "PayloadRestriction"; $Value = $PayloadRestriction }
            "FromSystemCallFilter" { $Policy = "SystemCallFilter"; $Value = $SystemCallFilter }
            "FromSideChannelIsolation" { $Policy = "SideChannelIsolation"; $Value = $SideChannelIsolation }
            "FromAslr" { $Policy = "ASLR"; $Value = $Aslr }
            "FromRedirectionTrust" { $Policy = "RedirectionTrust"; $Value = $RedirectionTrust }
        }
    }

    PROCESS {
        if ($null -eq $Process) {
            $Process = Get-NtProcess -Current
        }

        if ($FromRaw) {
            $Process.SetRawMitigationPolicy($Policy, $Value)
        }
        else {
            $Process.SetMitigationPolicy($Policy, $Value)
        }
    }
}

<#
.SYNOPSIS
Suspend a process.
.DESCRIPTION
This cmdlet suspends a process.
.PARAMETER Process
The process to suspend.
.INPUTS
NtApiDotNet.NtProcess
.OUTPUTS
None
#>
function Suspend-NtProcess {
    [CmdletBinding(DefaultParameterSetName = "FromProcess")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromProcess", ValueFromPipeline)]
        [NtApiDotNet.NtProcess[]]$Process
    )

    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "FromProcess" {
                foreach ($p in $Process) {
                    $p.Suspend()
                }
            }
        }
    }
}

<#
.SYNOPSIS
Resume a process.
.DESCRIPTION
This cmdlet resumes a process.
.PARAMETER Process
The process to resume.
.INPUTS
NtApiDotNet.NtProcess
.OUTPUTS
None
#>
function Resume-NtProcess {
    [CmdletBinding(DefaultParameterSetName = "FromProcess")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromProcess", ValueFromPipeline)]
        [NtApiDotNet.NtProcess[]]$Process
    )

    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "FromProcess" {
                foreach ($p in $Process) {
                    $p.Resume()
                }
            }
        }
    }
}

<#
.SYNOPSIS
Stop a process.
.DESCRIPTION
This cmdlet stops/kills a process with an optional status code.
.PARAMETER Process
The process to stop.
.PARAMETER ExitCode
The NTSTATUS exit code.
.PARAMETER ExitCodeInt
The exit code as an integer.
.INPUTS
NtApiDotNet.NtProcess
.OUTPUTS
None
#>
function Stop-NtProcess {
    [CmdletBinding(DefaultParameterSetName = "FromStatus")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline)]
        [NtApiDotNet.NtProcess[]]$Process,
        [Parameter(Position = 1, ParameterSetName = "FromStatus")]
        [NtApiDotNet.NtStatus]$ExitStatus = 0,
        [Parameter(Position = 1, ParameterSetName = "FromInt")]
        [int]$ExitCode = 0
    )

    PROCESS {
        foreach ($p in $Process) {
            switch ($PsCmdlet.ParameterSetName) {
                "FromStatus" { $p.Terminate($ExitStatus) }
                "FromInt" { $p.Terminate($ExitCode) }
            }
        }
    }
}

<#
.SYNOPSIS
Get user SID for a process.
.DESCRIPTION
This cmdlet will get the user SID for a process.
.PARAMETER Process
The process object.
.PARAMETER ProcessId
The PID of the process.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Sid
.EXAMPLE
Get-NtProcessUser -ProcessId 1234
Get user SID for process ID 1234.
.EXAMPLE
Get-NtProcessUser -Process $p
Get user SID for process.
#>
function Get-NtProcessUser {
    [CmdletBinding(DefaultParameterSetName = "FromProcessId")]
    Param(
        [parameter(ParameterSetName = "FromProcessId", Position = 0, Mandatory)]
        [alias("pid")]
        [int]$ProcessId,
        [parameter(ParameterSetName = "FromProcess", Mandatory)]
        [NtApiDotNet.NtProcess]$Process
    )
    switch ($PSCmdlet.ParameterSetName) {
        "FromProcessId" {
            Set-NtTokenPrivilege -Privilege SeDebugPrivilege -WarningAction SilentlyContinue
            Use-NtObject($p = Get-NtProcess -ProcessId $ProcessId -Access QueryLimitedInformation) {
                Get-NtProcessUser -Process $p | Write-Output
            }
        }
        "FromProcess" {
            $Process.User | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get environment variables from a process.
.DESCRIPTION
This cmdlet will get the environment variables from a process.
.PARAMETER Process
The process object.
.PARAMETER ProcessId
The process ID.
.PARAMETER Name
The name of the variable.
.INPUTS
None
.OUTPUTS
NtApiDotNet.NtProcessEnvironmentVariable[]
.EXAMPLE
Get-NtProcessEnvironment -ProcessId 1234
Get environment for process 1234.
.EXAMPLE
Get-NtProcessEnvironment -Process $p
Get environment for process.
.EXAMPLE
Get-NtProcessEnvironment -ProcessId 1234 -Name "TMP"
Get environment variable TMP for process 1234.
#>
function Get-NtProcessEnvironment {
    [CmdletBinding(DefaultParameterSetName = "FromProcessId")]
    Param(
        [parameter(ParameterSetName = "FromProcessId", Position = 0, Mandatory)]
        [alias("pid")]
        [int]$ProcessId,
        [parameter(ParameterSetName = "FromProcess", Mandatory)]
        [NtApiDotNet.NtProcess]$Process,
        [string]$Name
    )

    switch ($PSCmdlet.ParameterSetName) {
        "FromProcessId" {
            Set-NtTokenPrivilege -Privilege SeDebugPrivilege -WarningAction SilentlyContinue
            Use-NtObject($p = Get-NtProcess -ProcessId $ProcessId -Access VmRead, QueryLimitedInformation) {
                if ($Name -ne "") {
                    $p.GetEnvironmentVariable($Name) | Write-Output
                } else {
                    $p.GetEnvironment() | Write-Output
                }
            }
        }
        "FromProcess" {
            if ($Name -ne "") {
                $Process.GetEnvironmentVariable($Name) | Write-Output
            } else {
                $Process.GetEnvironment() | Write-Output
            }
        }
    }
}

<#
.SYNOPSIS
Checks if the process is in a Job or a specific Job.
.DESCRIPTION
This cmdlet checks if a process is in any Job or a specific Job.
.PARAMETER Process
Specify the process to check.
.PARAMETER Job
Specify a Job object to check. If not specified then will check for any Job.
.PARAMETER Current
Specify to check the current process.
.INPUTS
None
.OUTPUTS
Bool
.EXAMPLE
Test-NtProcessJob -Process $proc
Test if the process is a job.
.EXAMPLE
Test-NtProcessJob -Process $proc -Job $job
Test if the process is in a specific job.
.EXAMPLE
Test-NtProcessJob -Current
Test if the current process is a job.
.EXAMPLE
Test-NtProcessJob -Current -Job $job
Test if the current process is in a specific job.
#>
function Test-NtProcessJob {
    [CmdletBinding(DefaultParameterSetName="FromProcess")]
    param(
        [parameter(Mandatory, Position = 0, ParameterSetName="FromProcess")]
        [NtApiDotNet.NtProcess]$Process,
        [parameter(Position = 1)]
        [NtApiDotNet.NtJob]$Job,
        [parameter(Mandatory, ParameterSetName="FromCurrent")]
        [switch]$Current
    )
    if ($Current) {
        $Process = Get-NtProcess -Current
    }
    $Process.IsInJob($Job)
}

<#
.SYNOPSIS
Test if a process can be opened.
.DESCRIPTION
This cmdlet tests if a process can be opened. You can specify a specific access mask to check
or request the maximum access.
.PARAMETER ProcessId
Specify the process ID to check.
.PARAMETER Access
Specify the access to check.
.INPUTS
None
.OUTPUTS
Boolean
.EXAMPLE
Test-NtProcess -ProcessId 1234
Test if PID 1234 can be opened with maximum access.
.EXAMPLE
Test-NtProcess -ProcessId 1234 -Access DupHandle
Test if PID 1234 can be opened with DupHandle access.
#>
function Test-NtProcess {
    [CmdletBinding()]
    param (
        [alias("pid")]
        [parameter(Mandatory, Position = 0)]
        [int]$ProcessId,
        [NtApiDotNet.ProcessAccessRights]$Access = "MaximumAllowed"
    )

    Use-NtObject($proc = [NtApiDotNet.NtProcess]::Open($ProcessId, $Access, $false)) {
        $proc.IsSuccess
    }
}
