#  Copyright 2016, 2017 Google Inc. All Rights Reserved.
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

Set-StrictMode -Version Latest

if (($PSVersionTable.Keys -contains "PSEdition") -and ($PSVersionTable.PSEdition -ne 'Desktop')) {
  Import-Module "$PSScriptRoot\Core\NtObjectManager.dll"
}
else
{
  Import-Module "$PSScriptRoot\NtObjectManager.dll"
}

if ([System.Environment]::Is64BitProcess) {
    $native_dir = "$PSScriptRoot\x64"
} else {
    $native_dir = "$PSScriptRoot\x86"
}

if (Test-Path "$native_dir\dbghelp.dll") {
    $Script:GlobalDbgHelpPath = "$native_dir\dbghelp.dll"
} else {
    $Script:GlobalDbgHelpPath = "dbghelp.dll"
}

$Script:GlobalSymbolPath = "srv*https://msdl.microsoft.com/download/symbols"

<#
.SYNOPSIS
Get a list of ALPC Ports that can be opened by a specified token.
.DESCRIPTION
This cmdlet checks for all ALPC ports on the system and tries to determine if one or more specified tokens can connect to them.
If no tokens are specified then the current process token is used. This function searches handles for existing ALPC Port servers as you can't directly open the server object and just connecting might show inconsistent results.
.PARAMETER ProcessIds
Specify a list of process IDs to open for their tokens.
.PARAMETER ProcessNames
Specify a list of process names to open for their tokens.
.PARAMETER ProcessCommandLines
Specify a list of command lines to filter on find for the process tokens.
.PARAMETER Tokens
Specify a list token objects.
.PARAMETER Processes
Specify a list process objects to use for their tokens.
.INPUTS
None
.OUTPUTS
NtObjectManager.AccessCheckResult
.NOTES
For best results run this function as an administrator with SeDebugPrivilege available.
.EXAMPLE
Get-AccessibleAlpcPort
Get all ALPC Ports connectable by the current token.
.EXAMPLE
Get-AccessibleAlpcPort -ProcessIds 1234,5678
Get all ALPC Ports connectable by the process tokens of PIDs 1234 and 5678
#>
function Get-AccessibleAlpcPort {
  Param(
    [Int32[]]$ProcessIds,
    [string[]]$ProcessNames,
    [string[]]$ProcessCommandLines,
    [NtApiDotNet.NtToken[]]$Tokens,
    [NtApiDotNet.NtProcess[]]$Processes
    )
  $access = Get-NtAccessMask -AlpcPortAccess Connect -ToGenericAccess
  Get-AccessibleObject -FromHandles -ProcessIds $ProcessIds -ProcessNames $ProcessNames `
    -ProcessCommandLines $ProcessCommandLines -Tokens $Tokens -Processes $Processes -TypeFilter "ALPC Port" -AccessRights $access
}

<#
.SYNOPSIS
Set the state of a token's privileges.
.DESCRIPTION
This cmdlet will set the state of a token's privileges. This is commonly used to enable debug/backup privileges to perform privileged actions.
If no token is specified then the current process token is used.
.PARAMETER Privileges
A list of privileges to set their state.
.PARAMETER Token
Optional token object to use to set privileges. Must be accesible for AdjustPrivileges right.
.PARAMETER Attributes
Specify the actual attributes to set. Defaults to Enabled.
.INPUTS
None
.OUTPUTS
List of TokenPrivilege values indicating the new state of all privileges successfully modified.
.EXAMPLE
Set-NtTokenPrivilege SeDebugPrivilege
Enable SeDebugPrivilege on the current process token
.EXAMPLE
Set-NtTokenPrivilege SeDebugPrivilege -Attributes Disabled
Disable SeDebugPrivilege on the current process token
.EXAMPLE
Set-NtTokenPrivilege SeBackupPrivilege, SeRestorePrivilege -Token $token
Enable SeBackupPrivilege and SeRestorePrivilege on an explicit token object.
#>
function Set-NtTokenPrivilege
{
  Param(
    [Parameter(Mandatory=$true, Position=0)]
    [NtApiDotNet.TokenPrivilegeValue[]]$Privileges,
    [NtApiDotNet.NtToken]$Token,
    [NtApiDotNet.PrivilegeAttributes]$Attributes = "Enabled"
    )
  if ($null -eq $Token) {
    $Token = Get-NtToken -Primary
  } else {
    $Token = $Token.Duplicate()
  }

  Use-NtObject($Token) {
    $result = @()
    foreach($priv in $Privileges) {
      if ($Token.SetPrivilege($priv, $Attributes)) {
        $result += @($Token.GetPrivilege($priv))
      }
    }
    return $result
  }
}

<#
.SYNOPSIS
Set the integrity level of a token.
.DESCRIPTION
This cmdlet will set the integrity level of a token. If you want to raise the level you must have SeTcbPrivilege otherwise you can only lower it. 
If no token is specified then the current process token is used.
.PARAMETER IntegrityLevel
Specify the integrity level.
.PARAMETER Token
Optional token object to use to set privileges. Must be accesible for AdjustDefault right.
.PARAMETER Adjustment
Increment or decrement the IL level from the base specified in -IntegrityLevel.
.PARAMETER IntegrityLevelRaw
Specify the integrity level as a raw value.
.INPUTS
None
.EXAMPLE
Set-NtTokenIntegrityLevel Low
Set the current token's integrity level to low.
.EXAMPLE
Set-NtTokenIntegrityLevel Low -Token $Token
Set a specific token's integrity level to low.
.EXAMPLE
Set-NtTokenIntegrityLevel Low -Adjustment -16
Set the current token's integrity level to low minus 16.
.EXAMPLE
Set-NtTokenIntegrityLevel -IntegrityLevelRaw 0x800 
Set the current token's integrity level to 0x800.
#>
function Set-NtTokenIntegrityLevel
{
  [CmdletBinding(DefaultParameterSetName = "FromIL")]
  Param(
    [Parameter(Mandatory=$true, Position=0, ParameterSetName = "FromIL")]
    [NtApiDotNet.TokenIntegrityLevel]$IntegrityLevel,
    [NtApiDotNet.NtToken]$Token,
    [Parameter(ParameterSetName = "FromIL")]
    [Int32]$Adjustment = 0,
    [Parameter(Mandatory=$true, Position=0, ParameterSetName = "FromRaw")]
    [Int32]$IntegrityLevelRaw
    )
  switch($PSCmdlet.ParameterSetName) {
    "FromIL" {
        $il_raw = $IntegrityLevel.ToInt32($null) + $Adjustment
    }
    "FromRaw" {
        $il_raw = $IntegrityLevelRaw
    }
  }

  if ($Token -eq $null) {
    $Token = Get-NtToken -Primary
  } else {
    $Token = $Token.Duplicate()
  }

  Use-NtObject($Token) {
    $Token.SetIntegrityLevelRaw($il_raw) | Out-Null
  }
}

<#
.SYNOPSIS
Create a kernel crash dump.
.DESCRIPTION
This cmdlet will use the NtSystemDebugControl API to create a system kernel crash dump with specified options.
.PARAMETER Path
The NT native path to the crash dump file to create
.PARAMETER Flags
Optional flags to control what to dump
.PARAMETER PageFlags
Optional flags to control what additional pages to dump
.INPUTS
None
.EXAMPLE
New-NtKernelCrashDump \??\C:\memory.dmp
Create a new crash dump at c:\memory.dmp
.EXAMPLE
New-NtKernelCrashDump \??\C:\memory.dmp -Flags IncludeUserSpaceMemoryPages
Create a new crash dump at c:\memory.dmp including user memory pages.
#>
function New-NtKernelCrashDump
{
  Param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Path,
    [NtApiDotNet.SystemDebugKernelDumpControlFlags]$Flags = 0,
    [NtApiDotNet.SystemDebugKernelDumpPageControlFlags]$PageFlags = 0
  )
  [NtApiDotNet.NtSystemInfo]::CreateKernelDump($Path, $Flags, $PageFlags)
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
function Get-NtProcessMitigations
{
  [CmdletBinding(DefaultParameterSetName="All")]
  Param(
    [parameter(ParameterSetName="FromName")]
    [string]$Name,
    [parameter(ParameterSetName="FromProcessId")]
    [int[]]$ProcessId
  )
    Set-NtTokenPrivilege SeDebugPrivilege | Out-Null

    $ps = switch($PSCmdlet.ParameterSetName) {
        "All" {
            Get-NtProcess -Access QueryInformation
        }
        "FromName" {
            Get-NtProcess -Name $Name
        }
        "FromProcessId" {
            foreach($id in $ProcessId) {
                Get-NtProcess -ProcessId $id
            }
        }
    }
    Use-NtObject($ps) {
        foreach($p in $ps) {
            try {
                Write-Output $p.Mitigations
            } catch {
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
function New-NtObjectAttributes
{
  Param(
    [Parameter(Position=0)]
    [string]$Name,
    [NtApiDotNet.NtObject]$Root,
    [NtApiDotNet.AttributeFlags]$Attributes = "None",
    [NtApiDotNet.SecurityQualityOfService]$SecurityQualityOfService,
    [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
    [string]$Sddl
  )

  $sd = $SecurityDescriptor
  if ($Sddl -ne "")
  {
    $sd = New-NtSecurityDescriptor -Sddl $Sddl
  }

  [NtApiDotNet.ObjectAttributes]::new($Name, $Attributes, [NtApiDotNet.NtObject]$Root, $SecurityQualityOfService, $sd)
}

<#
.SYNOPSIS
Create a new security quality of service structure.
.DESCRIPTION
This cmdlet creates a new security quality of service structure structure based on its parameters
.PARAMETER ImpersonationLevel
The impersonation level, must be specified.
.PARAMETER ContextTrackingMode
Optional tracking mode, defaults to static tracking
.PARAMETER EffectiveOnly
Optional flag to specify if only the effective rights should be impersonated
.INPUTS
None
#>
function New-NtSecurityQualityOfService
{
  Param(
    [Parameter(Mandatory=$true, Position=0)]
    [NtApiDotNet.SecurityImpersonationLevel]$ImpersonationLevel,
    [NtApiDotNet.SecurityContextTrackingMode]$ContextTrackingMode = "Static",
    [switch]$EffectiveOnly
  )

  [NtApiDotNet.SecurityQualityOfService]::new($ImpersonationLevel, $ContextTrackingMode, $EffectiveOnly)
}

<#
.SYNOPSIS
Gets a list of system environment values
.DESCRIPTION
This cmdlet gets the list of system environment values. Note that this isn't the same as environment
variables, these are kernel values which represent current system state.
.PARAMETER Name
The name of the system environment value to get.
.INPUTS
None
#>
function Get-NtSystemEnvironmentValue
{
  Param(
    [Parameter(Position=0)]
    [string]$Name = [System.Management.Automation.Language.NullString]::Value
    )
  Set-NtTokenPrivilege SeSystemEnvironmentPrivilege | Out-Null
  $values = [NtApiDotNet.NtSystemInfo]::QuerySystemEnvironmentValueNamesAndValues()
  if ($Name -eq [string]::Empty) {
    $values
  } else {
    $values | Where-Object Name -eq $Name
  }
}

<#
.SYNOPSIS
Get a license value by name.
.DESCRIPTION
This cmdlet gets a license value by name
.PARAMETER Name
The name of the license value to get.
.INPUTS
None
.OUTPUTS
NtApiDotNet.NtKeyValue
#>
function Get-NtLicenseValue
{
  Param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Name
    )
    [NtApiDotNet.NtKey]::QueryLicenseValue($Name)
}

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
Specify to not fallback to using CreateProcessWithLogon if CreateProcessAsUser fails.
.PARAMETER AppContainerProfile
Specify an app container profile to use.
.PARAMETER ExtendedFlags
 Specify extended creation flags.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Win32ProcessConfig
#>
function New-Win32ProcessConfig
{
    Param(
        [Parameter(Mandatory=$true, Position=0)]
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
        [NtApiDotNet.Win32.ProcessExtendedFlags]$ExtendedFlags = 0
    )
    $config = New-Object NtApiDotNet.Win32.Win32ProcessConfig
    $config.CommandLine = $CommandLine
    if (-not [string]::IsNullOrEmpty($ApplicationName))
    {
        $config.ApplicationName = $ApplicationName
    }
    $config.ProcessSecurityDescriptor = $ProcessSecurityDescriptor
    $config.ThreadSecurityDescriptor = $ThreadSecurityDescriptor
    $config.ParentProcess = $ParentProcess
    $config.CreationFlags = $CreationFlags
    $config.TerminateOnDispose = $TerminateOnDispose
    $config.Environment = $Environment
    if (-not [string]::IsNullOrEmpty($Desktop))
    {
        $config.Desktop = $Desktop
    }
    if (-not [string]::IsNullOrEmpty($CurrentDirectory))
    {
        $config.CurrentDirectory = $CurrentDirectory
    }
    if (-not [string]::IsNullOrEmpty($Title))
    {
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
    }
    $config.ExtendedFlags = $ExtendedFlags
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
.PARAMETER Config
Specify the configuration for the new process.
.PARAMETER Wait
Specify to wait for the process to exit.
.PARAMETER WaitTimeout
Specify the timeout to wait for the process to exit. Defaults to infinite.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Win32Process
#>
function New-Win32Process
{
  [CmdletBinding(DefaultParameterSetName = "FromArgs")]
    Param(
        [Parameter(Mandatory=$true, Position=0, ParameterSetName = "FromArgs")]
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
        [Parameter(Mandatory=$true, Position=0, ParameterSetName = "FromConfig")]
        [NtApiDotNet.Win32.Win32ProcessConfig]$Config,
        [switch]$Wait,
        [NtApiDotNet.NtWaitTimeout]$WaitTimeout = [NtApiDotNet.NtWaitTimeout]::Infinite
    )

  if ($null -eq $Config) {
    $Config = New-Win32ProcessConfig $CommandLine -ApplicationName $ApplicationName `
    -ProcessSecurityDescriptor $ProcessSecurityDescriptor -ThreadSecurityDescriptor $ThreadSecurityDescriptor `
    -ParentProcess $ParentProcess -CreationFlags $CreationFlags -TerminateOnDispose:$TerminateOnDispose `
    -Environment $Environment -CurrentDirectory $CurrentDirectory -Desktop $Desktop -Title $Title `
    -InheritHandles:$InheritHandles -InheritProcessHandle:$InheritProcessHandle -InheritThreadHandle:$InheritThreadHandle `
    -MitigationOptions $MitigationOptions -Token $Token -ProtectionLevel $ProtectionLevel -NoTokenFallback:$NoTokenFallback `
    -DebugObject $DebugObject -AppContainerProfile $AppContainerProfile -ExtendedFlags $ExtendedFlags
  }

  $p = [NtApiDotNet.Win32.Win32Process]::CreateProcess($config)
  if ($Wait) {
    $p.Process.Wait($WaitTimeout)
  }
  $p | Write-Output
}

<#
.SYNOPSIS
Get the NT path for a dos path.
.DESCRIPTION
This cmdlet gets the full NT path for a specified DOS path.
.PARAMETER FullName
The DOS path to convert to NT.
.PARAMETER Resolve
Resolve relative paths to the current PS directory.
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
  [CmdletBinding()]
  Param(
    [alias("Path")]
    [parameter(Mandatory=$true, Position=0, ValueFromPipeline, valueFromPipelineByPropertyName)]
    [string]$FullName,
    [switch]$Resolve
  )

  PROCESS {
    $type = [NtApiDotNet.NtFileUtils]::GetDosPathType($FullName)
    $p = $FullName
    if ($Resolve) {
        if ($type -eq "Relative" -or $type -eq "Rooted") {
            $p = Resolve-Path -LiteralPath $FullName
        }
    }
    $p = [NtObjectManager.GetNtFileCmdlet]::ResolveWin32Path($PSCmdlet.SessionState, $p)
    Write-Output $p
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

.EXAMPLE
Get-NtFilePathType c:\Windows
Get the path type for c:\windows.
#>
function Get-NtFilePathType {
  Param(
    [parameter(Mandatory, Position=0)]
    [string]$FullName
  )

  [NtApiDotNet.NtFileUtils]::GetDosPathType($FullName)
}

<#
.SYNOPSIS
Create a new native NT process configuration.
.DESCRIPTION
This cmdlet creates a new native process configuration which you can then pass to New-NtProcess.
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
.INPUTS
None
.OUTPUTS
NtApiDotNet.CreateUserProcess
#>
function New-NtProcessConfig
{
    Param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$CommandLine,
    [NtApiDotNet.ProcessCreateFlags]$ProcessFlags = 0,
    [NtApiDotNet.ThreadCreateFlags]$ThreadFlags = 0,
    [NtApiDotNet.PsProtectedType]$ProtectedType = 0,
    [NtApiDotNet.PsProtectedSigner]$ProtectedSigner = 0,
    [switch]$TerminateOnDispose
    )
    $config = New-Object NtApiDotNet.CreateUserProcess
    $config.ProcessFlags = $ProcessFlags
    $config.ThreadFlags = $ThreadFlags
    $config.CommandLine = $CommandLine
    $config.TerminateOnDispose = $TerminateOnDispose

    if ($ProtectedType -ne 0 -or $ProtectedSigner -ne 0)
    {
        $config.AddProtectionLevel($ProtectedType, $ProtectedSigner)
        $config.ProcessFlags = $ProcessFlags -bor "ProtectedProcess"
    }

    return $config
}

<#
.SYNOPSIS
Create a new native NT process.
.DESCRIPTION
This cmdlet creates a new native NT process.
.PARAMETER ImagePath
NT path to executable.
.PARAMETER Config
The configuration for the new process from New-NtProcessConfig.
.PARAMETER Win32Path
Specified ImagePath is a Win32 path.
.INPUTS
None
.OUTPUTS
NtApiDotNet.CreateUserProcessResult
#>
function New-NtProcess
{
  [CmdletBinding(DefaultParameterSetName = "FromArgs")]
    Param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$ImagePath,
    [NtApiDotNet.CreateUserProcess]$Config,
    [switch]$Win32Path
    )

  if ($null -eq $Config) {
    $Config = New-NtProcessConfig -CommandLine $ImagePath
  }

  if ($Win32Path) {
    $ImagePath = Get-NtFilePath $ImagePath -Resolve
  }

  $Config.Start($ImagePath)
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
NtApiDotNet.EaBuffer
.EXAMPLE
New-NtEaBuffer
Create a new empty EaBuffer object
.EXAMPLE
New-NtEaBuffer @{ INTENTRY = 1234; STRENTRY = "ABC"; BYTEENTRY = [byte[]]@(1,2,3) }
Create a new EaBuffer object initialized with three separate entries.
#>
function New-NtEaBuffer
{
  [CmdletBinding(DefaultParameterSetName = "FromEntries")]
  Param(
    [Parameter(ParameterSetName = "FromEntries", Position = 0)]
    [Hashtable]$Entries = @{},
    [Parameter(ParameterSetName = "FromExisting", Position = 0)]
    [NtApiDotnet.Eabuffer]$ExistingBuffer
  )

  if ($null -eq $ExistingBuffer)
  {
    $ea_buffer = New-Object NtApiDotNet.EaBuffer
    foreach($entry in $Entries.Keys)
    {
      $ea_buffer.AddEntry($entry, $Entries.Item($entry), 0)
    }
    return $ea_buffer
  }
  else
  {
    return New-Object NtApiDotNet.EaBuffer -ArgumentList $ExistingBuffer
  }
}

<#
.SYNOPSIS
Create a new image section based on an existing file.
.DESCRIPTION
This cmdlet creates an image section based on an existing file.
.PARAMETER File
A file object to an image file to create.
.PARAMETER Path
A path to an image to create.
.PARAMETER Win32Path
Resolve path as a Win32 path
.PARAMETER ObjectPath
Specify an object path for the new section object.
.INPUTS
None
.OUTPUTS
NtApiDotNet.NtSection
.EXAMPLE
New-NtSectionImage -Path \??\c:\windows\notepad.exe
Creates a
.EXAMPLE
New-NtSectionImage -File $file
Creates a new image section from an open NtFile object.
#>
function New-NtSectionImage
{
  [CmdletBinding(DefaultParameterSetName = "FromFile")]
  Param(
    [Parameter(Position = 0, ParameterSetName = "FromFile", Mandatory = $true)]
    [NtApiDotNet.NtFile]$File,
    [Parameter(Position = 0, ParameterSetName = "FromPath", Mandatory = $true)]
    [string]$Path,
    [Parameter(ParameterSetName = "FromPath")]
    [switch]$Win32Path,
    [string]$ObjectPath
  )

  if ($null -eq $File)
  {
    if ($Win32Path)
    {
      $Path = Get-NtFilePath $Path -Resolve
    }
    Use-NtObject($new_file = Get-NtFile -Path $Path -Share Read,Delete -Access GenericExecute) {
      return [NtApiDotNet.NtSection]::CreateImageSection($ObjectPath, $new_file)
    }
  }
  else
  {
    return [NtApiDotNet.NtSection]::CreateImageSection($ObjectPath, $File)
  }
}

<#
.SYNOPSIS
Opens an impersonation token from a process or thread using NtImpersonateThread
.DESCRIPTION
This cmdlet opens an impersonation token from a process using NtImpersonateThread. While SeDebugPrivilege
allows you to bypass the security of processes and threads it doesn't mean you can open the primary token.
This cmdlet allows you to get past that by getting a handle to the first thread and then impersonating it,
as long as the thread isn't impersonating something else you'll get back a copy of the primary token.
.PARAMETER ProcessId
A process to open to get the token from.
.PARAMETER ThreadId
A thread to open to get the token from.
.PARAMETER Access
Access rights for the opened token.
.INPUTS
None
.OUTPUTS
NtApiDotNet.NtToken
.EXAMPLE
Get-NtTokenFromProcess -ProcessId 1234
Gets token from process ID 1234.
.EXAMPLE
Get-NtTokenFromProcess -ProcessId 1234 -Access Query
Gets token from process ID 1234 with only Query access.
.EXAMPLE
Get-NtTokenFromProcess -ThreadId 1234
Gets token from process ID 1234.
#>
function Get-NtTokenFromProcess
{
  [CmdletBinding(DefaultParameterSetName = "FromProcess")]
    Param(
    [Parameter(Position = 0, ParameterSetName = "FromProcess", Mandatory = $true)]
    [ValidateScript({$_ -ge 0})]
    [int]$ProcessId = -1,
    [Parameter(ParameterSetName = "FromThread", Mandatory = $true)]
    [ValidateScript({$_ -ge 0})]
    [int]$ThreadId = -1,
    [NtApiDotNet.TokenAccessRights]$Access = "MaximumAllowed"
    )

    Set-NtTokenPrivilege SeDebugPrivilege | Out-Null
  $t = $null

  try
  {
    if (-1 -ne $ProcessId)
    {
      $t = Use-NtObject($p = Get-NtProcess -ProcessId $ProcessId) {
        $p.GetFirstThread("DirectImpersonation")
      }
    }
    else
    {
      $t = Get-NtThread -ThreadId $ThreadId -Access DirectImpersonation
    }

    $current = Get-NtThread -Current -PseudoHandle
    Use-NtObject($t, $current.ImpersonateThread($t)) {
      Get-NtToken -Impersonation -Thread $current -Access $Access
    }
  }
  catch
  {
    Write-Error $_
  }
}

<#
.SYNOPSIS
Gets the executable manifest for a PE file.
.DESCRIPTION
This cmdlet extracts the manifes from a PE file and extracts basic information such as UIAccess
setting or Auto Elevation.
.PARAMETER Path
Filename to get the executable manifest from.
.INPUTS
List of filenames
.OUTPUTS
NtApiDotNet.Win32.ExecutableManifest
.EXAMPLE
Get-ExecutableManifest abc.dll
Gets manifest from file abc.dll.
.EXAMPLE
Get-ChildItem $env:windir\*.exe -Recurse | Get-ExecutableManifest
Gets all manifests from EXE files, recursively under Windows.
.EXAMPLE
Get-ChildItem $env:windir\*.exe -Recurse | Get-ExecutableManifest | Where-Object AutoElevate | Select-Object FullPath
Get the full path of all executables with Auto Elevate manifest configuration.
#>
function Get-ExecutableManifest
{
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [string]$Path
    )
    PROCESS {
        $fullpath = Resolve-Path -LiteralPath $Path
        $manifest = [NtApiDotNet.Win32.ExecutableManifest]::GetManifests($fullpath)
        Write-Output $manifest
    }
}

<#
.SYNOPSIS
Prints the details of the current token.
.DESCRIPTION
This cmdlet opens the current token and prints basic details about it. This is similar to the Windows whois
command but runs in process and will print information about the current thread token if you're impersonating.
.PARAMETER All
Show all information.
.PARAMETER User
Show user information.
.PARAMETER Group
Show group information. Also prints capability sids and restricted sids if a sandboxed token.
.PARAMETER Privilege
Show privilege information.
.PARAMETER Integrity
Show integrity information.
.OUTPUTS
Text data
.EXAMPLE
Show-NtTokenEffective
Show only the user name of the current token.
.EXAMPLE
Show-NtTokenEffective -All
Show the user, groups, privileges and integrity of the current token.
.EXAMPLE
Show-NtTokenEffective -User -Group
Show the user and groups of the current token.
#>
function Show-NtTokenEffective {
    Param(
    [switch]$All,
    [switch]$Group,
    [switch]$Privilege,
    [switch]$User,
    [switch]$Integrity
    )

  $token = Get-NtToken -Effective

  if ($All) {
    $Group = $true
    $User = $true
    $Privilege = $true
    $Integrity = $true
  }

  if (!$User -and !$Group -and !$Privilege -and !$Integrity) {
    $token.User.ToString()
    return
  }

  if ($User) {
    "USER INFORMATION"
    "----------------"
    $token.User | Format-Table
  }

  if ($Group) {
    "GROUP SID INFORMATION"
    "-----------------"
    $token.Groups | Format-Table

    if ($token.AppContainer) {
      "CAPABILITY SID INFORMATION"
      "----------------------"
      $token.Capabilities | Format-Table
    }

    if ($token.Restricted) {
      "RESTRICTED SID INFORMATION"
      "--------------------------"
      $token.RestrictedSids | Format-Table
    }
  }

  if ($Privilege) {
    "PRIVILEGE INFORMATION"
    "---------------------"
    $token.Privileges | Format-Table
  }

  if ($Integrity) {
    "INTEGRITY LEVEL"
    "---------------"
    $token.IntegrityLevel | Format-Table
  }
}

<#
.SYNOPSIS
Shows an object's security descriptor in a UI.
.DESCRIPTION
This cmdlet displays the security descriptor for an object in the standard Windows UI. If an object is passed
and the handle grants WriteDac access then the viewer will also allows you to modify the security descriptor.
.PARAMETER Object
Specify an object to use for the security descriptor.
.PARAMETER SecurityDescriptor
Specify a security descriptor.
.PARAMETER Type
Specify the NT object type for the security descriptor.
.PARAMETER Name
Optional name to display with the security descriptor.
.PARAMETER Wait
Optionally wait for the user to close the UI.
.PARAMETER ReadOnly
Optionally force the viewer to be read-only when passing an object with WriteDac access.
.OUTPUTS
None
.EXAMPLE
Show-NtSecurityDescriptor $obj
Show the security descriptor of an object.
.EXAMPLE
Show-NtSecurityDescriptor $obj -ReadOnly
Show the security descriptor of an object as read only.
.EXAMPLE
Show-NtSecurityDescriptor $obj.SecurityDescriptor -Type $obj.NtType
Show the security descriptor for an object via it's properties.
#>
function Show-NtSecurityDescriptor {
  [CmdletBinding(DefaultParameterSetName = "FromObject")]
    Param(
    [Parameter(Position = 0, ParameterSetName = "FromObject", Mandatory = $true)]
    [NtApiDotNet.NtObject]$Object,
    [Parameter(ParameterSetName = "FromObject")]
    [switch]$ReadOnly,
    [Parameter(Position = 0, ParameterSetName = "FromSecurityDescriptor", Mandatory = $true)]
    [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
    [Parameter(Position = 1, ParameterSetName = "FromSecurityDescriptor", Mandatory = $true)]
    [NtApiDotNet.NtType]$Type,
    [Parameter(ParameterSetName = "FromSecurityDescriptor")]
    [string]$Name = "Object",
    [switch]$Wait
    )

  switch($PsCmdlet.ParameterSetName) {
    "FromObject" {
        if (!$Object.IsAccessMaskGranted([NtApiDotNet.GenericAccessRights]::ReadControl)) {
            Write-Error "Object doesn't have Read Control access."
            return
        }
        # For some reason ALPC ports can't be passed to child processes. So instead pass as an SD.
        if ($Object.NtType.Name -eq "ALPC Port") {
            Show-NtSecurityDescriptor $Object.SecurityDescriptor $Object.NtType -Name $Object.Name -Wait:$Wait
            return
        }
        Use-NtObject($obj = $Object.Duplicate()) {
            $cmdline = [string]::Format("ViewSecurityDescriptor {0}", $obj.Handle.DangerousGetHandle())
            if ($ReadOnly) {
                $cmdline += " --readonly"
            }
            $config = New-Win32ProcessConfig $cmdline -ApplicationName "$PSScriptRoot\ViewSecurityDescriptor.exe" -InheritHandles
            $config.AddInheritedHandle($obj) | Out-Null
            Use-NtObject($p = New-Win32Process -Config $config) {
                if ($Wait) {
                    $p.Process.Wait() | Out-Null
                }
            }
        }
    }
    "FromSecurityDescriptor" {
        Start-Process -FilePath "$PSScriptRoot\ViewSecurityDescriptor.exe" -ArgumentList @("`"$Name`"", "`"$($SecurityDescriptor.ToSddl())`"","`"$($Type.Name)`"") -Wait:$Wait
    }
  }
}

function Format-NtAce {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline)]
        [NtApiDotNet.Ace]$Ace,
        [Parameter(Position = 1, Mandatory = $true)]
        [NtApiDotNet.NtType]$Type,
        [switch]$MapGeneric
    )

    PROCESS {
        $mask = $ace.Mask
        if ($MapGeneric) {
            $mask = $Type.MapGenericRights($mask)
        }

        $access_name = "Access"
        $mask_str = if ($ace.Type -eq "MandatoryLabel") {
            $mask.ToMandatoryLabelPolicy().ToString()
            $access_name = "Policy"
        } else {
            $Type.AccessMaskToString($mask, $MapGeneric)
        }

        Write-Output " - Type  : $($ace.Type)"
        Write-Output " - Name  : $($ace.Sid.Name)"
        Write-Output " - SID   : $($ace.Sid)"
        Write-Output " - Mask  : 0x$($mask.ToString("X08"))"
        Write-Output " - $($access_name): $mask_str"
        Write-Output " - Flags : $($ace.Flags)"
        if ($ace.IsConditionalAce) {
            Write-Output " - Condition: $($ace.Condition)"
        }
        Write-Output ""
    }
}

function Format-NtAcl {
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [NtApiDotNet.Acl]$Acl,
        [Parameter(Position = 1, Mandatory = $true)]
        [NtApiDotNet.NtType]$Type,
        [Parameter(Mandatory = $true)]
        [switch]$MapGeneric,
        [switch]$AuditOnly
    )

    if ($Acl.NullAcl) {
        Write-Output " - <NULL>"
    } else {
        if ($AuditOnly) {
            $Acl | ? IsAuditAce | Format-NtAce -Type $Type -MapGeneric:$MapGeneric
        } else {
            $Acl | Format-NtAce -Type $Type -MapGeneric:$MapGeneric
        }
    }
}

<#
.SYNOPSIS
Formats an object's security descriptor as text.
.DESCRIPTION
This cmdlet formats the security descriptor to text for display in the console or piped to a file.
.PARAMETER Object
Specify an object to use for the security descriptor.
.PARAMETER SecurityDescriptor
Specify a security descriptor.
.PARAMETER Type
Specify the NT object type for the security descriptor.
.PARAMETER Path
Specify the path to an NT object for the security descriptor.
.PARAMETER SecurityInformation
Specify what parts of the security descriptor to format.
.PARAMETER MapGeneric
Specify to map access masks back to generic access rights for the object type.
.OUTPUTS
None
.EXAMPLE
Format-NtSecurityDescriptor -Object $obj
Format the security descriptor of an object.
.EXAMPLE
Format-NtSecurityDescriptor -SecurityDescriptor $obj.SecurityDescriptor -Type $obj.NtType
Format the security descriptor for an object via it's properties.
.EXAMPLE
Format-NtSecurityDescriptor -Path \BaseNamedObjects
Format the security descriptor for an object from a path.
#>
function Format-NtSecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName = "FromObject")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromObject", Mandatory = $true, ValueFromPipeline)]
        [NtApiDotNet.NtObject]$Object,
        [Parameter(Position = 0, ParameterSetName = "FromSecurityDescriptor", Mandatory = $true, ValueFromPipeline)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, ParameterSetName = "FromSecurityDescriptor", Mandatory = $true)]
        [NtApiDotNet.NtType]$Type,
        [Parameter(Position = 0, ParameterSetName = "FromPath", Mandatory = $true, ValueFromPipeline)]
        [string]$Path,
        [NtApiDotNet.SecurityInformation]$SecurityInformation = "AllBasic",
        [switch]$MapGeneric
    )

    PROCESS {
        try {
            $sd, $t,$n = switch($PsCmdlet.ParameterSetName) {
                "FromObject" {
                    if (!$Object.IsAccessMaskGranted([NtApiDotNet.GenericAccessRights]::ReadControl)) {
                        Write-Error "Object doesn't have Read Control access."
                        return
                    }
                    ($Object.GetSecurityDescriptor($SecurityInformation), $Object.NtType, $Object.FullPath)
                }
                "FromPath" {
                    $access = "ReadControl"
                    if (($SecurityInformation -band "Sacl") -ne 0) {
                        $access += ", AccessSystemSecurity"
                    }
                    Use-NtObject($obj = Get-NtObject -Path $Path -Access $access) {
                        ($obj.GetSecurityDescriptor($SecurityInformation), $obj.NtType, $obj.FullPath)
                    }
                }
                "FromSecurityDescriptor" {
                    ($SecurityDescriptor, $Type, "UNKNOWN")
                }
            }

            Write-Output "Path: $n"
            Write-Output "Type: $($t.Name)"

            if ($sd.Owner -ne $null -and (($SecurityInformation -band "Owner") -ne 0)) {
                Write-Output "<Owner>"
                Write-Output " - Name     : $($sd.Owner.Sid.Name)"
                Write-Output " - Sid      : $($sd.Owner.Sid)"
                Write-Output " - Defaulted: $($sd.Owner.Defaulted)"
                Write-Output ""
            }
            if ($sd.Group -ne $null -and (($SecurityInformation -band "Group") -ne 0)) {
                Write-Output "<Group>"
                Write-Output " - Name     : $($sd.Group.Sid.Name)"
                Write-Output " - Sid      : $($sd.Group.Sid)"
                Write-Output " - Defaulted: $($sd.Group.Defaulted)"
                Write-Output ""
            }
            if ($sd.Dacl -ne $null -and (($SecurityInformation -band "Dacl") -ne 0)) {
                Write-Output "<DACL>"
                Format-NtAcl $sd.Dacl $t -MapGeneric:$MapGeneric
            }
            if ($sd.Sacl -ne $null  -and (($SecurityInformation -band "Sacl") -ne 0)) {
                Write-Output "<SACL>"
                Format-NtAcl $sd.Sacl $t -MapGeneric:$MapGeneric -AuditOnly
            }
            $label = $sd.GetMandatoryLabel()
            if ($label -ne $null -and (($SecurityInformation -band "Label") -ne 0)) {
                Write-Output "<Mandatory Label>" 
                Format-NtAce -Ace $label -Type $t
            }
            $trust = $sd.ProcessTrustLabel
            if ($trust -ne $null -and (($SecurityInformation -band "ProcessTrustLabel") -ne 0)) {
                Write-Output "<Process Trust Label>"
                Format-NtAce -Ace $trust -Type $t
            }
        } catch {
            Write-Error $_
        }
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
.OUTPUTS
NtApiDotNet.NtIoControlCode
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
#>
function Get-NtIoControlCode
{
    [CmdletBinding(DefaultParameterSetName = "FromCode")]
    Param(
    [Parameter(Position = 0, ParameterSetName = "FromCode", Mandatory = $true)]
    [int]$ControlCode,
    [Parameter(ParameterSetName = "FromParts", Mandatory = $true)]
    [NtApiDotNet.FileDeviceType]$DeviceType,
    [Parameter(ParameterSetName = "FromParts", Mandatory = $true)]
    [int]$Function,
    [Parameter(ParameterSetName = "FromParts", Mandatory = $true)]
    [NtApiDotNet.FileControlMethod]$Method,
    [Parameter(ParameterSetName = "FromParts", Mandatory = $true)]
    [NtApiDotNet.FileControlAccess]$Access,
    [Parameter(ParameterSetName = "FromParts")]
    [Parameter(ParameterSetName = "FromCode")]
    [switch]$LookupName,
    [Parameter(ParameterSetName = "FromAll", Mandatory = $true)]
    [switch]$All
    )
  $result = switch ($PsCmdlet.ParameterSetName) {
    "FromCode" {
        [NtApiDotNet.NtIoControlCode]::new($ControlCode)
    }
    "FromParts" {
        [NtApiDotNet.NtIoControlCode]::new($DeviceType, $Function, $Method, $Access)
    }
    "FromAll" {
        [NtApiDotNet.NtWellKnownIoControlCodes]::GetKnownControlCodes()
    }
  }

  if ($LookupName) {
    return [NtApiDotNet.NtWellKnownIoControlCodes]::KnownControlCodeToName($result)
  }
  $result
}

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
    [NtApiDotNet.NtObject]$Object
  )
    $obj = [PSCustomObject]@{ProcessId=$PID;Handle=$Object.Handle.DangerousGetHandle().ToInt32()}
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
NtApiDotNet.NtObject (the best available type).
.EXAMPLE
Import-NtObject '{"ProcessId":3300,"Handle":2660}'
Import an object from a JSON string.
.EXAMPLE
Import-NtObject -ProcessId 3300 -Handle 2660
Import an object from separate PID and handle values.
#>
function Import-NtObject {
    [CmdletBinding(DefaultParameterSetName="FromObject")]
    param(
    [Parameter(Position = 0, Mandatory, ParameterSetName = "FromObject")]
    [string]$Object,
    [Parameter(Position = 0, Mandatory, ParameterSetName = "FromPid")]
    [int]$ProcessId,
    [Parameter(Position = 1, Mandatory, ParameterSetName = "FromPid")]
    [int]$Handle
  )
    switch($PSCmdlet.ParameterSetName) {
        "FromObject" {
            $obj = ConvertFrom-Json $Object
            Import-NtObject -ProcessId $obj.ProcessId -Handle $obj.Handle
        }
        "FromPid" {
            Use-NtObject($generic = [NtApiDotNet.NtGeneric]::DuplicateFrom($ProcessId, $Handle)) {
                $generic.ToTypedObject()
            }
        }
    }
}

<#
.SYNOPSIS
Gets the execution alias information from a name.
.DESCRIPTION
This cmdlet looks up an execution alias and tries to parse its reparse point to extract internal information.
.PARAMETER AliasName
The alias name to lookup. Can be either a full path to the alias or a name which will be found in the WindowsApps
folder.
.EXAMPLE
Get-ExecutionAlias ubuntu.exe
Get the ubuntu.exe execution alias from local appdata.
.EXAMPLE
Get-ExecutionAlias c:\path\to\alias.exe
Get the alias.exe execution alias from an absolute path.
#>
function Get-ExecutionAlias
{
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$AliasName
        )

    if (Test-Path $AliasName) {
        $path = Resolve-Path $AliasName
    } else {
        $path = $env:LOCALAPPDATA + "\Microsoft\WindowsApps\$AliasName"
    }

    Use-NtObject($file = Get-NtFile -Path $path -Win32Path -Options OpenReparsePoint,SynchronousIoNonAlert `
                  -Access GenericRead,Synchronize) {
        $file.GetReparsePoint()
    }
}

<#
.SYNOPSIS
Creates a new execution alias information or updates and existing one.
.DESCRIPTION
This cmdlet creates a new execution alias for a packaged application.
.PARAMETER PackageName
The name of the UWP package.
.PARAMETER EntryPoint
The entry point of the application
.PARAMETER Target
The target executable path
.PARAMETER AppType
The application type.
.PARAMETER Version
Version number
.EXAMPLE
Set-ExecutionAlias c:\path\to\alias.exe -PackageName test -EntryPoint test!test -Target c:\test.exe -Flags 48 -Version 3
Set the alias.exe execution alias.
#>
function Set-ExecutionAlias
{
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Path,
        [Parameter(Mandatory=$true, Position=1)]
        [string]$PackageName,
        [Parameter(Mandatory=$true, Position=2)]
        [string]$EntryPoint,
        [Parameter(Mandatory=$true, Position=3)]
        [string]$Target,
        [NtApiDotNet.ExecutionAliasAppType]$AppType = "Desktop",
        [Int32]$Version = 3
    )

    $rp = [NtApiDotNet.ExecutionAliasReparseBuffer]::new($Version, $PackageName, $EntryPoint, $Target, $AppType)
    Use-NtObject($file = New-NtFile -Path $Path -Win32Path -Options OpenReparsePoint,SynchronousIoNonAlert `
                  -Access GenericWrite,Synchronize -Disposition OpenIf) {
            $file.SetReparsePoint($rp)
    }
}

function Start-NtTokenViewer {
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [NtApiDotNet.NtToken]$Token,
        [string]$Text
    )

    Use-NtObject($dup_token = $Token.Duplicate()) {
        $dup_token.Inherit = $true
        $cmdline = [string]::Format("TokenViewer --handle={0}", $dup_token.Handle.DangerousGetHandle())
        if ($Text -ne "") {
            $cmdline += " ""--text=$Text"""
        }
        $config = New-Win32ProcessConfig $cmdline -ApplicationName "$PSScriptRoot\TokenViewer.exe" -InheritHandles
        $config.InheritHandleList.Add($dup_token.Handle.DangerousGetHandle())
        Use-NtObject($p = New-Win32Process -Config $config) {
        }
    }
}

<#
.SYNOPSIS
Display a UI viewer for a NT token.
.DESCRIPTION
This function will create an instance of the TokenViewer application to display the opened token.
.PARAMETER Token
The token to view.
.PARAMETER Text
Additional text to show in title bar for this token.
.PARAMETER Process
The process to display the token for.
.PARAMETER ProcessId
A process ID of a process to display the token for.
.PARAMETER Name
The name of a process to display the token for.
.PARAMETER MaxTokens
When getting the name only display at most this number of tokens.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Show-NtToken
Display the primary token for the current process.
.EXAMPLE
Show-NtToken -ProcessId 1234
Display the primary token for the process with PID 1234.
.EXAMPLE
Show-NtToken -Process $process
Display the primary token for the process specified with an NtProcess object.
.EXAMPLE
$ps | Select-Object -First 5 | Show-NtToken
Display the first 5 primary tokens from a list of processes.
.EXAMPLE
Show-NtToken -Token $token
Display the token specified with an NtToken object.
.EXAMPLE
Show-NtToken -Name "notepad.exe"
Display the primary tokens from accessible processes named notepad.exe.
.EXAMPLE
Show-NtToken -Name "notepad.exe" -MaxTokens 5
Display up to 5 primary tokens from accessible processes named notepad.exe.
.EXAMPLE
Show-NtToken -All
Show a list of all accessible tokens to choose from.
#>
function Show-NtToken {
    [CmdletBinding(DefaultParameterSetName = "FromPid")]
    param(
        [Parameter(Mandatory=$true, Position=0, ParameterSetName="FromToken", ValueFromPipeline=$true)]
        [NtApiDotNet.NtToken]$Token,
        [Parameter(Mandatory=$true, Position=0, ParameterSetName="FromProcess", ValueFromPipeline=$true)]
        [NtApiDotNet.NtProcess]$Process,
        [Parameter(Position=0, ParameterSetName="FromPid")]
        [int]$ProcessId = $pid,
        [Parameter(Mandatory=$true, ParameterSetName="FromName")]
        [string]$Name,
        [int]$MaxTokens = 0,
        [Parameter(ParameterSetName="All")]
        [switch]$All
    )

    PROCESS {
      if (-not $(Test-Path "$PSScriptRoot\TokenViewer.exe" -PathType Leaf)) {
        Write-Error "Missing token viewer application $PSScriptRoot\TokenViewer.exe"
        return
      }
      switch($PSCmdlet.ParameterSetName) {
        "FromProcess" {
            Use-NtObject($t = Get-NtToken -Primary -Process $Process) {
              $text = "$($Process.Name):$($Process.ProcessId)"
              Start-NtTokenViewer $t -Text $text
            }
        }
        "FromName" {
          Use-NtObject($ps = Get-NtProcess -Name $Name -Access QueryLimitedInformation) {
            if ($MaxTokens -gt 0) {
              $ps = $ps | Select-Object -First $MaxTokens
            }
            $ps | Show-NtToken
          }
        }
        "FromPid" {
          $cmdline = [string]::Format("TokenViewer --pid={0}", $ProcessId)
          $config = New-Win32ProcessConfig $cmdline -ApplicationName "$PSScriptRoot\TokenViewer.exe" -InheritHandles
          Use-NtObject($p = New-Win32Process -Config $config) {
          }
        }
        "FromToken" {
          Start-NtTokenViewer $Token
        }
        "All" {
            Start-Process "$PSScriptRoot\TokenViewer.exe"
        }
      }
    }
}

<#
.SYNOPSIS
Invokes a script block while impersonating a token.
.DESCRIPTION
This cmdlet invokes a script block while impersonating a token. 
.PARAMETER Token
The token to impersonate, if the token is a primary token it will be duplicated.
.PARAMETER Script
The script block to execute during impersonation.
.PARAMETER ImpersonationLevel
When the token is duplicated specify the impersonation level to use.
.OUTPUTS
Result of the script block.
.EXAMPLE
Invoke-NtToken -Token $token -Script { Get-NtFile \Path\To\File }
Open a file under impersonation.
.EXAMPLE
Invoke-NtToken -Token $token -ImpersonationLevel Identification -Script { Get-NtToken -Impersonation -OpenAsSelf }
Open the impersontation token under identification level impersonation.
#>
function Invoke-NtToken{
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [NtApiDotNet.NtToken]$Token,
        [Parameter(Mandatory=$true, Position=1)]
        [ScriptBlock]$Script,
        [NtApiDotNet.SecurityImpersonationLevel]$ImpersonationLevel = "Impersonation"
    )

    if ($Token.TokenType -eq "Impersonation" -and $Token.ImpersonationLevel -lt $ImpersonationLevel) {
        Write-Error "Impersonation level can't be raised, specify an appropriate impersonation level"
        return
    }

    $cb = [System.Func[Object]]{ & $Script }
    $Token.RunUnderImpersonate($cb, $ImpersonationLevel)
}

<#
.SYNOPSIS
Displays a mapped section in a UI.
.DESCRIPTION
This cmdlet displays a section object inside a UI from where the data can be inspected or edited.
.PARAMETER Section
Specify a section object.
.PARAMETER Wait
Optionally wait for the user to close the UI.
.PARAMETER ReadOnly
Optionally force the viewer to be read-only when passing a section with Map Write access.
.PARAMETER Path
Path to a file to view as a section.
.PARAMETER ObjPath
Path to a object name to view as a section.
.OUTPUTS
None
.EXAMPLE
Show-NtSection $section
Show the mapped section.
.EXAMPLE
Show-NtSection $section -ReadOnly
Show the mapped section as read only.
.EXAMPLE
Show-NtSection $section -Wait
Show the mapped section and wait for the viewer to exit.
.EXAMPLE
Show-NtSection ([byte[]]@(0, 1, 2, 3))
Show an arbitrary byte array in the viewer.
.EXAMPLE
Show-NtSection path\to\file.bin
Show an arbitrary file in the viewer.
#>
function Show-NtSection {
    [CmdletBinding(DefaultParameterSetName = "FromSection")]
    Param(
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "FromSection")]
        [NtApiDotNet.NtSection]$Section,
        [Parameter(ParameterSetName = "FromSection")]
        [switch]$ReadOnly,
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "FromData")]
        [byte[]]$Data,
		[Parameter(Position = 0, Mandatory = $true, ParameterSetName = "FromFile")]
		[string]$Path,
		[Parameter(Position = 0, Mandatory = $true, ParameterSetName = "FromPath")]
		[string]$ObjPath,
        [switch]$Wait
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromSection" {
            if (!$Section.IsAccessGranted("MapRead")) {
                Write-Error "Section doesn't have Map Read access."
                return
            }
            Use-NtObject($obj = $Section.Duplicate()) {
                $obj.Inherit = $true
                $cmdline = [string]::Format("EditSection --handle {0}", $obj.Handle.DangerousGetHandle())
                if ($ReadOnly) {
                    $cmdline += " --readonly"
                }
                $config = New-Win32ProcessConfig $cmdline -ApplicationName "$PSScriptRoot\EditSection.exe" -InheritHandles
                $config.InheritHandleList.Add($obj.Handle.DangerousGetHandle())
                Use-NtObject($p = New-Win32Process -Config $config) {
                    if ($Wait) {
                        $p.Process.Wait() | Out-Null
                    }
                }
            }
        }
        "FromData" {
            if ($Data.Length -eq 0) {
                return
            }
            $tempfile = New-TemporaryFile
            $path = $tempfile.FullName
            [System.IO.File]::WriteAllBytes($path, $Data)
            Use-NtObject($p = New-Win32Process "EditSection --delete --file=""$path""" -ApplicationName "$PSScriptRoot\EditSection.exe") {
                if ($Wait) {
                    $p.Process.Wait() | Out-Null
                }
            }
        }
		"FromFile" {
		  $Path = Resolve-Path $Path
		  if ($Path -ne "") {
			Use-NtObject($p = New-Win32Process "EditSection --file=""$Path""" -ApplicationName "$PSScriptRoot\EditSection.exe") {
			  if ($Wait) {
				$p.Process.Wait() | Out-Null
			  }
			}
		  }
        }
		"FromPath" {
			Use-NtObject($p = New-Win32Process "EditSection --path=""$ObjPath""" -ApplicationName "$PSScriptRoot\EditSection.exe") {
				if ($Wait) {
					$p.Process.Wait() | Out-Null
				}
			}
		}
    } 
}

<#
.SYNOPSIS
Resolve the address of a list of objects.
.DESCRIPTION
This cmdlet resolves the kernel address for a list of objects. This is an expensive operation so it's designed to
be 
.PARAMETER Objects
The list of objects to resolve.
.OUTPUTS
None
.EXAMPLE
Resolve-NtObjectAddress $obj1, $obj2; $obj1.Address
Resolve the address of two objects.
#>
function Resolve-NtObjectAddress
{
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [NtApiDotNet.NtObject[]]$Objects
    )
    BEGIN {
        $objs = @()
    }
    PROCESS {
        $objs += $Objects
    }
    END {
        [NtApiDotNet.NtSystemInfo]::ResolveObjectAddress([NtApiDotNet.NtObject[]]$objs)
    }
}

<#
.SYNOPSIS
Get the security descriptor from an object.
.DESCRIPTION
This cmdlet gets the security descriptor from an object with specified list of security information.
.PARAMETER Object
The object to get the security descriptor from.
.PARAMETER SecurityInformation
The security information to get from the object.
.PARAMETER ToSddl
Convert the security descriptor to an SDDL string.
.PARAMETER Process
Specify process to a read a security descriptor from memory.
.PARAMETER Address
Specify the address in the process to read the security descriptor.
.PARAMETER Path
Specify an object path to get the security descriptor from.
.PARAMETER TypeName
Specify the type name of the object at Path. Needed if the module cannot automatically determine the NT type to open.
.INPUTS
NtApiDotNet.NtObject[]
.OUTPUTS
NtApiDotNet.SecurityDescriptor
string
.EXAMPLE
Get-NtSecurityDescriptor $obj
Get the security descriptor with default security information.
.EXAMPLE
Get-NtSecurityDescriptor $obj Dacl,Owner,Group
Get the security descriptor with DACL, OWNER and GROUP values.
.EXAMPLE
Get-NtSecurityDescriptor $obj Dacl -ToSddl
Get the security descriptor with DACL and output as an SDDL string.
.EXAMPLE
Get-NtSecurityDescriptor \BaseNamedObjects\ABC
Get the security descriptor from path \BaseNamedObjects\ABC.
.EXAMPLE
Get-NtSecurityDescriptor \??\C:\Windows -TypeName File
Get the security descriptor from c:\windows. Needs explicit NtType name of File to work.
.EXAMPLE
@($obj1, $obj2) | Get-NtSecurityDescriptor
Get the security descriptors from an array of objects.
.EXAMPLE
Get-NtSecurityDescriptor -Process $process -Address 0x12345678
Get the security descriptor from another process at address 0x12345678.
#>
function Get-NtSecurityDescriptor
{
    [CmdletBinding(DefaultParameterSetName = "FromObject")]
    param (
        [parameter(Mandatory, Position=0, ValueFromPipeline, ParameterSetName = "FromObject")]
        [NtApiDotNet.NtObject]$Object,
        [parameter(Position=1, ParameterSetName = "FromObject")]
        [NtApiDotNet.SecurityInformation]$SecurityInformation = "AllBasic",
        [parameter(Mandatory, ParameterSetName = "FromProcess")]
        [NtApiDotNet.NtProcess]$Process,
        [parameter(Mandatory, ParameterSetName = "FromProcess")]
        [int64]$Address,
        [parameter(Mandatory, Position=0, ParameterSetName = "FromPath")]
        [string]$Path,
        [parameter(ParameterSetName = "FromPath")]
        [string]$TypeName,
        [switch]$ToSddl
    )
    PROCESS {
        $sd = switch($PsCmdlet.ParameterSetName) {
            "FromObject" {
                $Object.GetSecurityDescriptor($SecurityInformation)
            }
            "FromProcess" {
                [NtApiDotNet.SecurityDescriptor]::new($Process, [IntPtr]::new($Address))
            }
            "FromPath" {
                Use-NtObject($obj = Get-NtObject -Path $Path -TypeName $TypeName -Access ReadControl) {
                    $obj.GetSecurityDescriptor($SecurityInformation)
                }
            }
        }
        if ($ToSddl) {
            $sd.ToSddl($SecurityInformation)
        } else {
            $sd
        }
    }
}

<#
.SYNOPSIS
Set the security descriptor for an object.
.DESCRIPTION
This cmdlet sets the security descriptor for an object with specified list of security information.
.PARAMETER Object
The object to set the security descriptor to.
.PARAMETER SecurityInformation
The security information to set obj the object.
.PARAMETER Path
Specify an object path to set the security descriptor to.
.PARAMETER TypeName
Specify the type name of the object at Path. Needed if the module cannot automatically determine the NT type to open.
.PARAMETER SecurityDescriptor
The security descriptor to set. Can specify an SDDL string which will be auto-converted.
.INPUTS
NtApiDotNet.NtObject[]
.OUTPUTS
None
.EXAMPLE
Set-NtSecurityDescriptor $obj $sd Dacl
Set the DACL of an object using a SecurityDescriptor object.
.EXAMPLE
Set-NtSecurityDescriptor $obj "D:(A;;GA;;;WD)" Dacl
Set the DACL of an object based on an SDDL string.
#>
function Set-NtSecurityDescriptor
{
    [CmdletBinding(DefaultParameterSetName = "ToObject")]
    param (
        [parameter(Mandatory, Position=0, ValueFromPipeline, ParameterSetName = "ToObject")]
        [NtApiDotNet.NtObject]$Object,
        [parameter(Mandatory, Position=0, ParameterSetName = "ToPath")]
        [string]$Path,
        [parameter(Mandatory, Position=1)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [parameter(Mandatory, Position=2)]
        [NtApiDotNet.SecurityInformation]$SecurityInformation,
        [parameter(ParameterSetName = "ToPath")]
        [string]$TypeName
        
    )
    PROCESS {
        switch($PsCmdlet.ParameterSetName) {
            "ToObject" {
                $Object.SetSecurityDescriptor($SecurityDescriptor, $SecurityInformation)
            }
            "ToPath" {
                $access = [NtApiDotNet.GenericAccessRights]::WriteDac
                if (($SecurityInformation -band "Owner, Label") -ne 0) {
                    $access = $access -bor "WriteOwner"
                }
                if (($SecurityInformation -band "Sacl") -ne 0) {
                    $access = $access -bor "AccessSystemSecurity"
                }

                Use-NtObject($obj = Get-NtObject -Path $Path -TypeName $TypeName -Access $access) {
                    $obj.SetSecurityDescriptor($SecurityDescriptor, $SecurityInformation)
                }
            }
        }
    }
}

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
.OUTPUTS
int64
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
function Add-NtVirtualMemory
{
    param (
        [parameter(Mandatory, Position=0)]
        [int64]$Size,
        [int64]$BaseAddress,
        [NtApiDotNet.NtProcess]$Process = [NtApiDotnet.NtProcess]::Current,
        [NtApiDotNet.MemoryAllocationType]$AllocationType = "Reserve, Commit",
        [NtApiDotNet.MemoryAllocationProtect]$Protection = "ReadWrite"
    )
    $Process.AllocateMemory($BaseAddress, $Size, $AllocationType, $Protection)
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
function Remove-NtVirtualMemory
{
    param (
        [parameter(Mandatory, Position=0)]
        [int64]$Address,
        [int64]$Size,
        [NtApiDotNet.MemoryFreeType]$FreeType = "Release",
        [NtApiDotNet.NtProcess]$Process = [NtApiDotnet.NtProcess]::Current
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
.PARAMETER IncludeFree
When showing all memory regions specify to include free regions as well.
.OUTPUTS
NtApiDotNet.MemoryInformation
.EXAMPLE
Get-NtVirtualMemory $addr
Get the memory information for the specified address.
.EXAMPLE
Get-NtVirtualMemory $addr -Process $process
Get the memory information for the specified address in another process.
.EXAMPLE
Get-NtVirtualMemory -All
Get all memory information.
.EXAMPLE
Get-NtVirtualMemory -All -Process $process
Get all memory information in another process.
.EXAMPLE
Get-NtVirtualMemory -All -Process $process -IncludeFree
Get all memory information in another process including free regions.
#>
function Get-NtVirtualMemory
{
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position=0, ParameterSetName = "FromAddress")]
        [int64]$Address,
        [NtApiDotNet.NtProcess]$Process = [NtApiDotnet.NtProcess]::Current,
        [parameter(Mandatory, ParameterSetName = "All")]
        [switch]$All,
        [parameter(ParameterSetName = "All")]
        [switch]$IncludeFree
    )
    switch ($PsCmdlet.ParameterSetName) {
    "FromAddress" {
      $Process.QueryMemoryInformation($Address)
    }
    "All" {
      $Process.QueryAllMemoryInformation($IncludeFree)
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
NtApiDotNet.MemoryAllocationProtect - The previous memory protection setting.
.EXAMPLE
Set-NtVirtualMemory $addr 0x1000 ExecuteRead
Sets the protection of a memory region to ExecuteRead.
#>
function Set-NtVirtualMemory
{
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position=0)]
        [int64]$Address,
        [parameter(Mandatory, Position=1)]
        [int64]$Size,
        [parameter(Mandatory, Position=2)]
        [NtApiDotNet.MemoryAllocationProtect]$Protection,
        [NtApiDotNet.NtProcess]$Process = [NtApiDotnet.NtProcess]::Current
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
#>
function Read-NtVirtualMemory
{
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position=0)]
        [int64]$Address,
        [parameter(Mandatory, Position=1)]
        [int]$Size,
        [NtApiDotNet.NtProcess]$Process = [NtApiDotnet.NtProcess]::Current,
        [switch]$ReadAll
    )
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
.OUTPUTS
int - The length of bytes successfully written.
.EXAMPLE
Write-NtVirtualMemory $addr 0, 1, 2, 3, 4
Write 5 bytes to $addr
.EXAMPLE
Write-NtVirtualMemory $addr 0, 1, 2, 3, 4 -Process $process
Write 5 bytes to $addr in another process.
#>
function Write-NtVirtualMemory
{
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position=0)]
        [int64]$Address,
        [parameter(Mandatory, Position=1)]
        [byte[]]$Data,
        [NtApiDotNet.NtProcess]$Process = [NtApiDotnet.NtProcess]::Current
    )
    $Process.WriteMemory($Address, $Data)
}

<#
.SYNOPSIS
Get the embedded signature information from a file.
.DESCRIPTION
This cmdlet gets the embedded authenticode signature information from a file. This differs
from Get-AuthenticodeSignature in that it doesn't take into account catalog signing which is
important for tracking down PP and PPL executables.
.PARAMETER FullName
The path to the file to extract the signature from.
#>
function Get-EmbeddedAuthenticodeSignature {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName=$true)]
        [string]$FullName
    )
    PROCESS {
        $content_type = [System.Security.Cryptography.X509Certificates.X509ContentType]::Unknown
        try {
            $path = Resolve-Path $FullName
            $content_type = [System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($Path)
        } catch {
        }

        if ($content_type -ne "Authenticode") {
            return
        }
        
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Path)
        $ppl = $false
        $pp = $false
        $tcb = $false
        $system = $false
        $dynamic = $false
        $elam = $false
        $store = $false

        foreach($eku in $cert.EnhancedKeyUsageList) {
           switch($eku.ObjectId) {
                "1.3.6.1.4.1.311.10.3.22" { $ppl = $true }
                "1.3.6.1.4.1.311.10.3.24" { $pp = $true }
                "1.3.6.1.4.1.311.10.3.23" { $tcb = $true }
                "1.3.6.1.4.1.311.10.3.6" { $system = $true }
                "1.3.6.1.4.1.311.76.11.1" { $elam = $true }
                "1.3.6.1.4.1.311.76.5.1" { $dynamic = $true }
                "1.3.6.1.4.311.76.3.1" { $store = $true }
            }
        }

        $props = @{
            Path=$Path;
            Certificate=$cert;
            ProtectedProcess=$pp;
            ProtectedProcessLight=$ppl;
            Tcb=$tcb;
            SystemComponent=$system;
            DynamicCodeGeneration=$dynamic;
            Elam=$elam;
            Store=$store;
        }
        $obj = New-Object –TypeName PSObject –Prop $props
        Write-Output $obj
    }
}

<#
.SYNOPSIS
Get the name for a SID.
.DESCRIPTION
This cmdlet looks up a name for a SID and returns the name with a source for where the name came from.
.PARAMETER Sid
The SID to lookup the name for.
.PARAMETER BypassCache
Specify to bypass the name cache for this lookup.
.OUTPUTS
NtApiDotNet.SidName - The looked up SID name.
.EXAMPLE
Get-NtSidName "S-1-1-0"
Lookup the name for the SID S-1-1-0.
.EXAMPLE
Get-NtSidName "S-1-1-0" -BypassCache
Lookup the name for the SID S-1-1-0 without checking the name cache.
#>
function Get-NtSidName {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position=0, ValueFromPipelineByPropertyName)]
        [NtApiDotNet.Sid]$Sid,
        [switch]$BypassCache
    )

    PROCESS {
        [NtApiDotNet.NtSecurity]::GetNameForSid($Sid, $BypassCache)
    }
}

<#
.SYNOPSIS
Creates a symbol resolver for a process.
.DESCRIPTION
This cmdlet creates a new symbol resolver for the given process.
.PARAMETER Process
The process to create the symbol resolver on. If not specified then the current process is used.
.PARAMETER DbgHelpPath
Specify path to a dbghelp DLL to use for symbol resolving. This should be ideally the dbghelp from debugging tool for Windows
which will allow symbol servers however you can use the system version if you just want to pull symbols locally.
.PARAMETER SymbolPath
Specify path for the symbols. If not specified it will first use the _NT_SYMBOL_PATH environment variable then use the 
default of 'srv*https://msdl.microsoft.com/download/symbols'
.OUTPUTS
NtApiDotNet.Win32.ISymbolResolver - The symbol resolver. Dispose after use.
.EXAMPLE
New-SymbolResolver
Get a symbol resolver for the current process with default settings.
.EXAMPLE
New-SymbolResolver -SymbolPath "c:\symbols"
Get a symbol resolver specifying for the current process specifying symbols in c:\symbols.
.EXAMPLE
New-SymbolResolver -Process $p -DbgHelpPath "c:\path\to\dbghelp.dll" -SymbolPath "srv*c:\symbols*https://blah.com/symbols"
Get a symbol resolver specifying a dbghelp path and symbol path and a specific process.
#>
function New-SymbolResolver {
    Param(
        [NtApiDotNet.NtProcess]$Process,
        [string]$DbgHelpPath,
        [string]$SymbolPath
    )
  if ($DbgHelpPath -eq "") {
    $DbgHelpPath = $Script:GlobalDbgHelpPath
  }
  if ($SymbolPath -eq "") {
    $SymbolPath = $env:_NT_SYMBOL_PATH
    if ($SymbolPath -eq "") {
      $SymbolPath = $Script:GlobalSymbolPath
    }
  }
  if ($Process -eq $null) {
    $Process = Get-NtProcess -Current
  }
  [NtApiDotNet.Win32.SymbolResolver]::Create($Process, $DbgHelpPath, $SymbolPath)
}

<#
.SYNOPSIS
Creates a NDR parser for a process.
.DESCRIPTION
This cmdlet creates a new NDR parser for the given process.
.PARAMETER Process
The process to create the NDR parser on. If not specified then the current process is used.
.PARAMETER SymbolResolver
Specify a symbol resolver for the parser. Note that this should be a resolver for the same process as we're parsing.
.PARAMETER ParserFlags
Specify flags which affect the parsing operation.
.OUTPUTS
NtApiDotNet.Ndr.NdrParser - The NDR parser.
.EXAMPLE
$ndr = New-NdrParser
Get an NDR parser for the current process.
.EXAMPLE
New-NdrParser -Process $p -SymbolResolver $resolver
Get an NDR parser for a specific process with a known resolver.
#>
function New-NdrParser {
    Param(
        [NtApiDotNet.NtProcess]$Process,
        [NtApiDotNet.Win32.ISymbolResolver]$SymbolResolver,
        [NtApiDotNet.Ndr.NdrParserFlags]$ParserFlags = 0
    )
    [NtApiDotNet.Ndr.NdrParser]::new($Process, $SymbolResolver, $ParserFlags)
}

function Convert-HashTableToIidNames {
    Param(
        [Hashtable]$IidToName,
        [NtApiDotNet.Ndr.NdrComProxyDefinition[]]$Proxy
    )
    $dict = [System.Collections.Generic.Dictionary[Guid, string]]::new()
    if ($IidToName -ne $null) {
        foreach($pair in $IidToName.GetEnumerator()) {
            $guid = [Guid]::new($pair.Key)
            $dict.Add($guid, $pair.Value)
        }
    }

    if ($Proxy -ne $null) {
        foreach($p in $Proxy) {
            $dict.Add($p.Iid, $p.Name)
        }
    }

    if (!$dict.ContainsKey("00000000-0000-0000-C000-000000000046")) {
        $dict.Add("00000000-0000-0000-C000-000000000046", "IUnknown")
    }

    if (!$dict.ContainsKey("00020400-0000-0000-C000-000000000046")) {
        $dict.Add("00020400-0000-0000-C000-000000000046", "IDispatch")
    }

    return $dict
}

<#
.SYNOPSIS
Parses COM proxy information from a DLL.
.DESCRIPTION
This cmdlet parses the COM proxy information from a specified DLL.
.PARAMETER Path
The path to the DLL containing the COM proxy information.
.PARAMETER Clsid
Optional CLSID for the object used to find the proxy information.
.PARAMETER Iids
Optional list of IIDs to parse from the proxy information.
.PARAMETER ParserFlags
Specify flags which affect the parsing operation.
.OUTPUTS
The parsed proxy information and complex types.
.EXAMPLE
$p = Get-NdrComProxy c:\path\to\proxy.dll
Parse the proxy information from c:\path\to\proxy.dll
.EXAMPLE
$p = Get-NdrComProxy $env:SystemRoot\system32\combase.dll -Clsid "00000320-0000-0000-C000-000000000046"
Parse the proxy information from combase.dll with a specific proxy CLSID.
.EXAMPLE
$p = Get-NdrComProxy $env:SystemRoot\system32\combase.dll -Clsid "00000320-0000-0000-C000-000000000046" -Iid "00000001-0000-0000-c000-000000000046"
Parse the proxy information from combase.dll with a specific proxy CLSID, only returning a specific IID.
#>
function Get-NdrComProxy {
    Param(
        [parameter(Mandatory, Position=0)]
        [string]$Path,
        [Guid]$Clsid = [Guid]::Empty,
        [NtApiDotNet.Win32.ISymbolResolver]$SymbolResolver,
        [Guid[]]$Iid,
        [NtApiDotNet.Ndr.NdrParserFlags]$ParserFlags = 0
    )
    $Path = Resolve-Path $Path -ErrorAction Stop
    Use-NtObject($parser = New-NdrParser -SymbolResolver $SymbolResolver -NdrParserFlags $ParserFlags) {
        $proxies = $parser.ReadFromComProxyFile($Path, $Clsid, $Iid)
        $props = @{
            Path=$Path;
            Proxies=$proxies;
            ComplexTypes=$parser.ComplexTypes;
            IidToNames=Convert-HashTableToIidNames -Proxy $proxies;
        }
        $obj = New-Object –TypeName PSObject –Prop $props
        Write-Output $obj
    }
}

<#
.SYNOPSIS
Format an NDR procedure.
.DESCRIPTION
This cmdlet formats a parsed NDR procedure.
.PARAMETER Procedure
The procedure to format.
.PARAMETER IidToName
A dictionary of IID to name mappings for parameters.
.OUTPUTS
string - The formatted procedure.
.EXAMPLE
Format-NdrProcedure $proc
Format a procedure.
.EXAMPLE
$procs = | Format-NdrProcedure
Format a list of procedures from a pipeline.
.EXAMPLE
Format-NdrProcedure $proc -IidToName @{"00000000-0000-0000-C000-000000000046"="IUnknown";}
Format a procedure with a known IID to name mapping.
#>
function Format-NdrProcedure {
  [CmdletBinding()]
    Param(
    [parameter(Mandatory, Position=0, ValueFromPipeline = $true)]
    [NtApiDotNet.Ndr.NdrProcedureDefinition]$Procedure,
    [Hashtable]$IidToName
    )

  BEGIN {
    $dict = Convert-HashTableToIidNames($IidToName)
    $formatter = [NtApiDotNet.Ndr.DefaultNdrFormatter]::Create($dict)
  }

  PROCESS {
    $fmt = $formatter.FormatProcedure($Procedure)
    Write-Output $fmt
  }
}

<#
.SYNOPSIS
Format an NDR complex type.
.DESCRIPTION
This cmdlet formats a parsed NDR complex type.
.PARAMETER ComplexType
The complex type to format.
.PARAMETER IidToName
A dictionary of IID to name mappings for parameters.
.OUTPUTS
string - The formatted complex type.
.EXAMPLE
Format-NdrComplexType $type
Format a complex type.
.EXAMPLE
$ndr.ComplexTypes | Format-NdrComplexType
Format a list of complex types from a pipeline.
.EXAMPLE
Format-NdrComplexType $type -IidToName @{"00000000-0000-0000-C000-000000000046"="IUnknown";}
Format a complex type with a known IID to name mapping.
#>
function Format-NdrComplexType {
  [CmdletBinding()]
    Param(
    [parameter(Mandatory, Position=0, ValueFromPipeline)]
    [NtApiDotNet.Ndr.NdrComplexTypeReference[]]$ComplexType,
    [Hashtable]$IidToName
    )

  BEGIN {
    $dict = Convert-HashTableToIidNames($IidToName)
    $formatter = [NtApiDotNet.Ndr.DefaultNdrFormatter]::Create($dict)
  }

  PROCESS {
    foreach($t in $ComplexType) {
        $formatter.FormatComplexType($t) | Write-Output
    }
  }
}

<#
.SYNOPSIS
Format an NDR COM proxy.
.DESCRIPTION
This cmdlet formats a parsed NDR COM proxy.
.PARAMETER Proxy
The proxy to format.
.PARAMETER IidToName
A dictionary of IID to name mappings for parameters.
.PARAMETER DemangleComName
A script block which demangles a COM name (for WinRT types)
.OUTPUTS
string - The formatted proxy.
.EXAMPLE
Format-NdrComProxy $proxy
Format a COM proxy.
.EXAMPLE
$proxies = | Format-NdrComProxy
Format a list of COM proxies from a pipeline.
.EXAMPLE
Format-NdrComProxy $proxy -IidToName @{"00000000-0000-0000-C000-000000000046"="IUnknown";}
Format a COM proxy with a known IID to name mapping.
#>
function Format-NdrComProxy {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position=0, ValueFromPipeline)]
        [NtApiDotNet.Ndr.NdrComProxyDefinition]$Proxy,
        [Hashtable]$IidToName,
        [ScriptBlock]$DemangleComName
    )

    BEGIN {
        $dict = Convert-HashTableToIidNames($IidToName)
        $formatter = if ($DemangleComName -eq $null) {
            [NtApiDotNet.Ndr.DefaultNdrFormatter]::Create($dict)
        } else {
            [NtApiDotNet.Ndr.DefaultNdrFormatter]::Create($dict, [Func[string, string]]$DemangleComName)
        }
    }

    PROCESS {
        $fmt = $formatter.FormatComProxy($Proxy)
        Write-Output $fmt
    }
}

<#
.SYNOPSIS
Parses RPC server information from an executable.
.DESCRIPTION
This cmdlet parses the RPC server information from a specified executable with a known offset.
.PARAMETER Path
The path to the executable containing the RPC server information.
.PARAMETER Offset
The offset into the executable where the RPC_SERVER_INTERFACE structure is loaded.
.PARAMETER ParserFlags
Specify flags which affect the parsing operation.
.OUTPUTS
The parsed RPC server information and complex types.
.EXAMPLE
$p = Get-NdrRpcServerInterface c:\path\to\server.dll 0x18000
Parse the RPC server information from c:\path\to\proxy.dll with offset 0x18000
#>
function Get-NdrRpcServerInterface {
    Param(
        [parameter(Mandatory, Position=0)]
        [string]$Path,
        [parameter(Mandatory, Position=1)]
        [int]$Offset,
        [NtApiDotNet.Win32.ISymbolResolver]$SymbolResolver,
        [NtApiDotNet.Ndr.NdrParserFlags]$ParserFlags = 0
    )
    $Path = Resolve-Path $Path -ErrorAction Stop
    Use-NtObject($parser = New-NdrParser -SymbolResolver $SymbolResolver -ParserFlags $ParserFlags) {
        $rpc_server = $parser.ReadFromRpcServerInterface($Path, $Offset)
        $props = @{
            Path=$Path;
            RpcServer=$rpc_server;
            ComplexTypes=$parser.ComplexTypes;
        }
        $obj = New-Object –TypeName PSObject –Prop $props
        Write-Output $obj
    }
}

<#
.SYNOPSIS
Format an RPC server interface type.
.DESCRIPTION
This cmdlet formats a parsed RPC server interface type.
.PARAMETER RpcServer
The RPC server interface to format.
.OUTPUTS
string - The formatted RPC server interface.
.EXAMPLE
Format-NdrRpcServerInterface $type
Format an RPC server interface type.
#>
function Format-NdrRpcServerInterface {
    [CmdletBinding()]
    Param(
    [parameter(Mandatory, Position=0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [NtApiDotNet.Ndr.NdrRpcServerInterface]$RpcServer
    )

  BEGIN {
    $formatter = [NtApiDotNet.Ndr.DefaultNdrFormatter]::Create()
  }

  PROCESS {
    $fmt = $formatter.FormatRpcServerInterface($RpcServer)
    Write-Output $fmt
  }
}

<#
.SYNOPSIS
Get a mapped view of a section.
.DESCRIPTION
This cmdlet calls the Map method on a section to map it into memory.
.PARAMETER Section
The section object to map.
.PARAMETER Protection
The protection of the mapping.
.PARAMETER Process
Optional process to map the section into. Default is the current process.
.PARAMETER ViewSize
The size of the view to map, 0 means map the entire section.
.PARAMETER BaseAddress
Base address for the mapping, 0 means pick a location.
.PARAMETER ZeroBits
The number of zero bits in the mapping address.
.PARAMETER CommitSize
The size of memory to commit from the section.
.PARAMETER SectionOffset
Offset into the section for the base address.
.PARAMETER SectionInherit
Inheritance flags for the section.
.PARAMETER AllocationType
The allocation type for the mapping.
.OUTPUTS
NtApiDotNet.NtMappedSection - The mapped section.
.EXAMPLE
Get-NtMappedSection -Section $sect -Protection ReadWrite
Map the section as Read/Write.
.EXAMPLE
Get-NtMappedSection -Section $sect -Protection ReadWrite -ViewSize 4096
Map the first 4096 bytes of the section as Read/Write.
.EXAMPLE
Get-NtMappedSection -Section $sect -Protection ReadWrite -SectionOffset (64*1024)
Map the section starting from offset 64k.
#>
function Get-NtMappedSection {
    Param(
        [parameter(Mandatory, Position=0)]
        [NtApiDotNet.NtSection]$Section,
        [parameter(Mandatory, Position=1)]
        [NtApiDotNet.MemoryAllocationProtect]$Protection,
        [NtApiDotNet.NtProcess]$Process,
        [IntPtr]$ViewSize=0,
        [IntPtr]$BaseAddress=0, 
        [IntPtr]$ZeroBits=0,
        [IntPtr]$CommitSize=0,
        [NtApiDotNet.LargeInteger]$SectionOffset,
        [NtApiDotNet.SectionInherit]$SectionInherit=[NtApiDotNet.SectionInherit]::ViewUnmap,
        [NtApiDotNet.AllocationType]$AllocationType="None"
    )

    if ($Process -eq $null) {
        $Process = Get-NtProcess -Current
    }

    $Section.Map($Process, $Protection, $ViewSize, $BaseAddress, `
            $ZeroBits, $CommitSize, $SectionOffset, `
            $SectionInherit, $AllocationType)
}

<#
.SYNOPSIS
Get registered WNF subscription.
.DESCRIPTION
This cmdlet gets the registered WNF entries or a specific entry from a state name.
.PARAMETER StateName
The statename to get.
.PARAMETER DontCheckExists
Specify to not check that the WNF entry exists.
.OUTPUTS
NtApiDotNet.NtWnf
.EXAMPLE
Get-NtWnf
Get all registered WNF entries.
.EXAMPLE
Get-NtWnf 0x12345678 
Get a WNF entry from a state name.
.EXAMPLE
Get-NtWnf 0x12345678 -DontCheckExists
Get a WNF entry from a state name but don't check if it exists.
#>
function Get-NtWnf {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Position=0, Mandatory, ParameterSetName="StateName")]
        [uint64]$StateName,
        [parameter(ParameterSetName="StateName")]
        [switch]$DontCheckExists
    )
    switch($PSCmdlet.ParameterSetName) {
        "All" {
            [NtApiDotNet.NtWnf]::GetRegisteredNotifications()
        }
        "StateName" { 
            [NtApiDotNet.NtWnf]::Open($StateName, -not $DontCheckExists)
        }
    }
}

<#
.SYNOPSIS
Get the cached signing level for a file.
.DESCRIPTION
This cmdlet gets the cached signing level for a specified file.
.PARAMETER Path
The file to get the cached signing level from.
.PARAMETER Win32Path
Specify to treat Path as a Win32 path.
.PARAMETER FromEa
Specify whether to the read the cached signing level from the extended attribute.
.OUTPUTS
NtApiDotNet.CachedSigningLevel
.EXAMPLE
Get-NtCachedSigningLevel \??\c:\path\to\file.dll
Get the cached signing level from \??\c:\path\to\file.dll
.EXAMPLE
Get-NtCachedSigningLevel c:\path\to\file.dll -Win32Path
Get the cached signing level from c:\path\to\file.dll converting from a win32 path.
.EXAMPLE
Get-NtCachedSigningLevel \??\c:\path\to\file.dll -FromEa
Get the cached signing level from \??\c:\path\to\file.dll using the extended attribute.
#>
function Get-NtCachedSigningLevel {
    Param(
        [parameter(Position=0, Mandatory)]
        [string]$Path,
        [switch]$Win32Path,
        [switch]$FromEa
    )

    $access = if ($FromEa) {
        [NtApiDotNet.FileAccessRights]::ReadEa
    } else {
        [NtApiDotNet.FileAccessRights]::ReadData
    }

    Use-NtObject($f = Get-NtFile $Path -Win32Path:$Win32Path -Access $access -ShareMode Read) {
        if ($FromEa) {
            $f.GetCachedSigningLevelFromEa();
        } else {
            $f.GetCachedSigningLevel()
        }
    }
}

<#
.SYNOPSIS
Adds an ACE to a security descriptor DACL.
.DESCRIPTION
This cmdlet adds a new ACE to a security descriptor DACL.
.PARAMETER SecurityDescriptor
The security descriptor to add the ACE to.
.PARAMETER Sid
The SID to add to the ACE.
.PARAMETER Name
The username to add to the ACE.
.PARAMETER KnownSid
A known SID to add to the ACE.
.PARAMETER AccessMask
The access mask for the ACE.
.PARAMETER GenericAccess
A generic access mask for the ACE.
.PARAMETER Type
The type of the ACE.
.PARAMETER Flags
The flags for the ACE.
.PARAMETER Condition
The condition string for the ACE.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Add-NtSecurityDescriptorDaclAce -SecurityDescriptor $sd -Sid "S-1-1-0" -AccessMask 0x1234
Adds an access allowed ACE to the DACL for SID S-1-1-0 and mask of 0x1234
.EXAMPLE
Add-NtSecurityDescriptorDaclAce -SecurityDescriptor $sd -Sid "S-1-1-0" -AccessMask (Get-NtAccessMask -FileAccess ReadData)
Adds an access allowed ACE to the DACL for SID S-1-1-0 and mask for the file ReadData access right.
#>
function Add-NtSecurityDescriptorDaclAce {
    [CmdletBinding(DefaultParameterSetName = "FromSid")]
    Param(
        [parameter(Position=0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [parameter(Mandatory, ParameterSetName="FromSid")]
        [NtApiDotNet.Sid]$Sid,
        [parameter(Mandatory, ParameterSetName="FromName")]
        [string]$Name,
        [parameter(Mandatory, ParameterSetName="FromKnownSid")]
        [NtApiDotNet.KnownSidValue]$KnownSid,
        [NtApiDotNet.AccessMask]$AccessMask = 0,
        [NtApiDotNet.GenericAccessRights]$GenericAccess = 0,
        [NtApiDotNet.AceType]$Type = "Allowed",
        [NtApiDotNet.AceFlags]$Flags = "None",
        [string]$Condition
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromSid" {
            # Do nothing.
        }
        "FromName" { 
            $Sid = Get-NtSid -Name $Name
        }
        "FromKnownSid" {
            $Sid = Get-NtSid -KnownSid $KnownSid
        }
    }

    $AccessMask = $AccessMask.Access -bor [uint32]$GenericAccess

    if ($null -ne $Sid) {
        $ace = [NtApiDotNet.Ace]::new($Type, $Flags, $AccessMask, $Sid)
        if ($Condition -ne "") {
            $ace.Condition = $Condition
        }
        $SecurityDescriptor.AddAce($ace)
    }
}

<#
.SYNOPSIS
Creates a new "fake" NT type object.
.DESCRIPTION
This cmdlet creates a new "fake" NT type object which can be used to do access checking for objects which aren't real NT types.
.PARAMETER Name
The name of the "fake" type.
.PARAMETER GenericRead
The value of GenericRead for the GENERIC_MAPPING.
.PARAMETER GenericWrite
The value of GenericWrite for the GENERIC_MAPPING.
.PARAMETER GenericExecute
The value of GenericExecute for the GENERIC_MAPPING.
.PARAMETER GenericAll
The value of GenericAll for the GENERIC_MAPPING.
.PARAMETER AccessRightsType
The enumerated type 
.INPUTS
None
.OUTPUTS
NtApiDotNet.NtType
.EXAMPLE
Add-NtSecurityDescriptorDaclAce -SecurityDescriptor $sd -Sid "S-1-1-0" -AccessMask 0x1234
Adds an access allowed ACE to the DACL for SID S-1-1-0 and mask of 0x1234
.EXAMPLE
Add-NtSecurityDescriptorDaclAce -SecurityDescriptor $sd -Sid "S-1-1-0" -AccessMask (Get-NtAccessMask -FileAccess ReadData)
Adds an access allowed ACE to the DACL for SID S-1-1-0 and mask for the file ReadData access right.
#>
function New-NtType {
    Param(
        [parameter(Position=0, Mandatory)]
        [string]$Name,
        [System.Type]$AccessRightsType = [NtApiDotNet.GenericAccessRights],
        [NtApiDotNet.AccessMask]$GenericRead = 0,
        [NtApiDotNet.AccessMask]$GenericWrite = 0,
        [NtApiDotNet.AccessMask]$GenericExecute = 0,
        [NtApiDotNet.AccessMask]$GenericAll = 0
    )

    [NtApiDotNet.NtType]::GetFakeType($Name, $GenericRead, $GenericWrite, $GenericExecute, $GenericAll, $AccessRightsType)
}

<#
.SYNOPSIS
Gets an ALPC server port.
.DESCRIPTION
This cmdlet gets an ALPC server port by name. As you can't directly open the server end of the port this function goes through
all handles and tries to extract the port from the hosting process. This might require elevated privileges, especially debug 
privilege, to work correctly.
.PARAMETER Path
The path to the ALPC server port to get.
.PARAMETER ProcessId
The process ID of the process to query for ALPC servers.
.INPUTS
None
.OUTPUTS
NtApiDotNet.NtAlpc
.EXAMPLE
Get-NtAlpcServer
Gets all ALPC server objects accessible to the current process.
.EXAMPLE
Get-NtAlpcServer "\RPC Control\atsvc"
Gets the "\RPC Control\atsvc" ALPC server.
.EXAMPLE
Get-NtAlpcServer -ProcessId 1234
Gets all ALPC servers from PID 1234.
#>
function Get-NtAlpcServer {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
       [parameter(Mandatory, Position=0, ParameterSetName = "FromPath")]
       [string]$Path,
       [parameter(Mandatory, Position=0, ParameterSetName = "FromProcessId")]
       [alias("pid")]
       [int]$ProcessId = -1
    )

    if (![NtApiDotNet.NtToken]::EnableDebugPrivilege()) {
        Write-Warning "Can't enable debug privilege, results might be incomplete"
    }
    $hs = Get-NtHandle -ObjectTypes "ALPC Port" -ProcessId $ProcessId | ? Name -ne ""

    switch($PSCmdlet.ParameterSetName) {
        "All" {
            Write-Output $hs.GetObject()
        }
        "FromProcessId" {
            Write-Output $hs.GetObject()
        }
        "FromPath" {
            foreach($h in $hs) {
                if ($h.Name -eq $Path) {
                    Write-Output $h.GetObject()
                    break
                }
            }
        }
    }
}

<#
.SYNOPSIS
Gets the endpoints for a RPC interface from the local endpoint mapper.
.DESCRIPTION
This cmdlet gets the endpoints for a RPC interface from the local endpoint mapper. Not all RPC interfaces
are registered in the endpoint mapper so it might not show.
.PARAMETER InterfaceId
The UUID of the RPC interface.
.PARAMETER InterfaceVersion
The version of the RPC interface.
.PARAMETER Server
Parsed NDR server.
.PARAMETER Binding
A RPC binding string to query all endpoints from.
.PARAMETER AlpcPort
An ALPC port name. Can contain a full path as long as the string contains \RPC Control\ (case sensitive).
.INPUTS
None or NtApiDotNet.Ndr.NdrRpcServerInterface
.OUTPUTS
NtApiDotNet.Win32.RpcEndpoint[]
.EXAMPLE
Get-RpcEndpoint
Get all RPC registered RPC endpoints.
.EXAMPLE
Get-RpcEndpoint $Server
Get RPC endpoints for a parsed NDR server interface.
.EXAMPLE
Get-RpcEndpoint "A57A4ED7-0B59-4950-9CB1-E600A665154F"
Get RPC endpoints for a specified interface ID ignoring the version.
.EXAMPLE
Get-RpcEndpoint "A57A4ED7-0B59-4950-9CB1-E600A665154F" "1.0"
Get RPC endpoints for a specified interface ID and version.
.EXAMPLE
Get-RpcEndpoint -Binding "ncalrpc:[RPC_PORT]"
Get RPC endpoints for exposed over ncalrpc with name RPC_PORT.
.EXAMPLE
Get-RpcEndpoint -AlpcPort "RPC_PORT"
Get RPC endpoints for exposed over ALPC with name RPC_PORT.
#>
function Get-RpcEndpoint {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
       [parameter(Mandatory, Position=0, ParameterSetName = "FromId")]
       [parameter(Mandatory, Position=0, ParameterSetName = "FromIdAndVersion")]
       [string]$InterfaceId,
       [parameter(Mandatory, Position=1, ParameterSetName = "FromIdAndVersion")]
       [Version]$InterfaceVersion,
       [parameter(Mandatory, Position=0, ParameterSetName = "FromServer", ValueFromPipeline)]
       [NtApiDotNet.Ndr.NdrRpcServerInterface]$Server,
       [parameter(Mandatory, ParameterSetName = "FromBinding")]
       [string]$Binding,
       [parameter(Mandatory, ParameterSetName = "FromAlpc")]
       [string]$AlpcPort
    )

    PROCESS {
        switch($PsCmdlet.ParameterSetName) {
            "All" {
                [NtApiDotNet.Win32.RpcEndpointMapper]::QueryEndpoints()
            }
            "FromId" {
                [NtApiDotNet.Win32.RpcEndpointMapper]::QueryEndpoints($InterfaceId)
            }
            "FromIdAndVersion" {
                [NtApiDotNet.Win32.RpcEndpointMapper]::QueryEndpoints($InterfaceId, $InterfaceVersion)
            }
            "FromServer" {
                [NtApiDotNet.Win32.RpcEndpointMapper]::QueryEndpoints($Server)
            }
            "FromBinding" {
                [NtApiDotNet.Win32.RpcEndpointMapper]::QueryEndpointsForBinding($Binding)
            }
            "FromAlpc" {
                [NtApiDotNet.Win32.RpcEndpointMapper]::QueryEndpointsForAlpcPort($AlpcPort)
            }
        }
    }
}

<#
.SYNOPSIS
Get the RPC servers from a DLL.
.DESCRIPTION
This cmdlet parses the RPC servers from a DLL. Note that in order to parse 32 bit DLLs you must run this module in 32 bit PowerShell.
.PARAMETER FullName
The path to the DLL.
.PARAMETER DbgHelpPath
Specify path to a dbghelp DLL to use for symbol resolving. This should be ideally the dbghelp from debugging tool for Windows
which will allow symbol servers however you can use the system version if you just want to pull symbols locally.
.PARAMETER SymbolPath
Specify path for the symbols. If not specified it will first use the _NT_SYMBOL_PATH environment variable then use the 
default of 'srv*https://msdl.microsoft.com/download/symbols'
.PARAMETER AsText
Return the results as text rather than objects.
.PARAMETER RemoveComments
When outputing as text remove comments from the output.
.PARAMETER ParseClients
Also parse client interface information, otherwise only servers are returned.
.PARAMETER IgnoreSymbols
Don't resolve any symbol information.
.PARAMETER SerializedPath
Path to a serialized representation of the RPC servers.
.INPUTS
string[] List of paths to DLLs.
.OUTPUTS
RpcServer[] The parsed RPC servers.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll
Get the list of RPC servers from rpcss.dll.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll -AsText
Get the list of RPC servers from rpcss.dll, return it as text.
.EXAMPLE
Get-ChildItem c:\windows\system32\*.dll | Get-RpcServer
Get the list of RPC servers from all DLLs in system32, return it as text.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll -DbgHelpPath c:\windbg\x64\dbghelp.dll
Get the list of RPC servers from rpcss.dll, specifying a different DBGHELP for symbol resolving.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll -SymbolPath c:\symbols
Get the list of RPC servers from rpcss.dll, specifying a different symbol path.
.EXAMPLE
Get-RpcServer -SerializedPath rpc.bin
Get the list of RPC servers from the serialized file rpc.bin.
#>
function Get-RpcServer {
  [CmdletBinding(DefaultParameterSetName="FromDll")]
  Param(
    [parameter(Mandatory=$true, Position=0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName="FromDll")]
    [alias("Path")]
    [string]$FullName,
    [parameter(ParameterSetName="FromDll")]
    [string]$DbgHelpPath,
    [parameter(ParameterSetName="FromDll")]
    [string]$SymbolPath,
    [parameter(ParameterSetName="FromDll")]
    [switch]$AsText,
    [parameter(ParameterSetName="FromDll")]
    [switch]$RemoveComments,
    [parameter(ParameterSetName="FromDll")]
    [switch]$ParseClients,
    [parameter(ParameterSetName="FromDll")]
    [switch]$IgnoreSymbols,
    [parameter(Mandatory=$true, ParameterSetName="FromSerialized")]
    [string]$SerializedPath
  )

  BEGIN {
    if ($DbgHelpPath -eq "") {
        $DbgHelpPath = $Script:GlobalDbgHelpPath
    }
    if ($SymbolPath -eq "") {
        $SymbolPath = $env:_NT_SYMBOL_PATH
        if ($SymbolPath -eq "") {
            $SymbolPath = $Script:GlobalSymbolPath
        }
    }
  }

  PROCESS {
    try {
        if ($PSCmdlet.ParameterSetName -eq "FromDll") {
            $FullName = Resolve-Path -LiteralPath $FullName -ErrorAction Stop
            Write-Progress -Activity "Parsing RPC Servers" -CurrentOperation "$FullName"
            $servers = [NtApiDotNet.Win32.RpcServer]::ParsePeFile($FullName, $DbgHelpPath, $SymbolPath, $ParseClients, $IgnoreSymbols)
            if ($AsText) {
                foreach($server in $servers) {
                    $text = $server.FormatAsText($RemoveComments)
                    Write-Output $text
                }
            } else {
                Write-Output $servers
            }
        } else {
            $FullName = Resolve-Path -LiteralPath $SerializedPath -ErrorAction Stop
            Use-NtObject($stm = [System.IO.File]::OpenRead($FullName)) {
                while($stm.Position -lt $stm.Length) {
                    [NtApiDotNet.Win32.RpcServer]::Deserialize($stm) | Write-Output
                }
            }
        }
    } catch {
        Write-Error $_
    }
  }
}

<#
.SYNOPSIS
Set a list RPC servers to a file for storage.
.DESCRIPTION
This cmdlet serializes a list of RPC servers to a file. This can be restored using Get-RpcServer -SerializedPath.
.PARAMETER Path
The path to the output file.
.PARAMETER Server
The list of servers to serialize.
.INPUTS
RpcServer[] List of paths to DLLs.
.OUTPUTS
None
.EXAMPLE
Set-RpcServer -Server $server -Path rpc.bin
Serialize servers to file rpc.bin.
#>
function Set-RpcServer {
  Param(
    [parameter(Mandatory=$true, Position=0, ValueFromPipeline)]
    [NtApiDotNet.Win32.RpcServer[]]$Server,
    [parameter(Mandatory=$true, Position=1)]
    [string]$Path
  )

  BEGIN {
    "" | Set-Content -Path $Path
    $Path = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    $stm = [System.IO.File]::Create($Path)
  }

  PROCESS {
    try {
        foreach($s in $Server) {
            $s.Serialize($stm)
        }
    } catch {
        Write-Error $_
    }
  }

  END {
    $stm.Close()
  }
}

<#
.SYNOPSIS
Format the RPC servers as text.
.DESCRIPTION
This cmdlet formats a list of RPC servers as text.
.PARAMETER RpcServer
The RPC servers to format.
.PARAMETER RemoveComments
When outputing as text remove comments from the output.
.INPUTS
RpcServer[] The RPC servers to format.
.OUTPUTS
string[] The formatted RPC servers.
.EXAMPLE
Format-RpcServer $rpc
Format list of RPC servers in $rpc.
.EXAMPLE
Format-RpcServer $rpc -RemoveComments
Format list of RPC servers in $rpc without comments.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll | Format-RpcServer
Get the list of RPC servers from rpcss.dll and format them.
#>
function Format-RpcServer {
  [CmdletBinding()]
  Param(
    [parameter(Mandatory=$true, Position=0, ValueFromPipeline)]
    [NtApiDotNet.Win32.RpcServer[]]$RpcServer,
    [switch]$RemoveComments
  )

  PROCESS {
    foreach($server in $RpcServer) {
        $server.FormatAsText($RemoveComments) | Write-Output
    }
  }
}

<#
.SYNOPSIS
Gets a list of ALPC RPC servers.
.DESCRIPTION
This cmdlet gets a list of ALPC RPC servers. This relies on being able to access the list of ALPC ports in side a process so might need elevated privileges.
.PARAMETER ProcessId
The ID of a process to query for ALPC servers.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.RpcAlpcServer[]
.EXAMPLE
Get-RpcAlpcServer
Get all ALPC RPC servers.
.EXAMPLE
Get-RpcAlpcServer -ProcessId 1234
Get all ALPC RPC servers in process ID 1234.
#>
function Get-RpcAlpcServer {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
       [parameter(Mandatory, Position=0, ParameterSetName = "FromProcessId")]
       [int]$ProcessId
    )

    Set-NtTokenPrivilege SeDebugPrivilege | Out-Null
    switch($PsCmdlet.ParameterSetName) {
        "All" {
            [NtApiDotNet.Win32.RpcAlpcServer]::GetAlpcServers()
        }
        "FromProcessId" {
            [NtApiDotNet.Win32.RpcAlpcServer]::GetAlpcServers($ProcessId)
        }
    }
}

<#
.SYNOPSIS
Sets the global symbol resolver paths.
.DESCRIPTION
This cmdlet sets the global symbol resolver paths. This allows you to specify symbol resolver paths for cmdlets which support it.
.PARAMETER DbgHelpPath
Specify path to a dbghelp DLL to use for symbol resolving. This should be ideally the dbghelp from debugging tool for Windows
which will allow symbol servers however you can use the system version if you just want to pull symbols locally.
.PARAMETER SymbolPath
Specify path for the symbols.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-GlobalSymbolResolver -DbgHelpPath c:\windbg\x64\dbghelp.dll
Specify the global dbghelp path.
.EXAMPLE
Set-GlobalSymbolResolver -DbgHelpPath dbghelp.dll -SymbolPath "c:\symbols"
Specify the global dbghelp path using c:\symbols to source the symbol files.
#>
function Set-GlobalSymbolResolver {
    Param(
        [parameter(Mandatory, Position=0)]
        [string]$DbgHelpPath,
        [parameter(Position=1)]
        [string]$SymbolPath
    )

    $Script:GlobalDbgHelpPath = $DbgHelpPath
    if ("" -ne $SymbolPath) {
        $Script:GlobalSymbolPath = $SymbolPath
    }
}

<#
.SYNOPSIS
Gets a list of running services.
.DESCRIPTION
This cmdlet gets a list of running services. It can also include in the list non-active services.
.PARAMETER IncludeNonActive
Specify to return all services including non-active ones.
.PARAMETER Name
Specify a name to lookup.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.RunningService[]
.EXAMPLE
Get-RunningService
Get all running services.
.EXAMPLE
Get-RunningService -IncludeNonActive
Get all running services including non-active services.
.EXAMPLE
Get-RunningService -Name Fax
Get the Fax running services.
#>
function Get-RunningService {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(ParameterSetName = "All")]
        [switch]$IncludeNonActive,
        [parameter(ParameterSetName = "FromName")]
        [string]$Name
    )

    switch($PSCmdlet.ParameterSetName) {
        "All" {
            if ($IncludeNonActive) {
                [NtApiDotNet.Win32.ServiceUtils]::GetServices()
            } else {
                [NtApiDotNet.Win32.ServiceUtils]::GetRunningServicesWithProcessIds()
            }
        }
        "FromName" {
            [NtApiDotNet.Win32.ServiceUtils]::GetServices() | ? Name -eq $Name
        }
    }
}

<#
.SYNOPSIS
Duplicates a token to a new token.
.DESCRIPTION
This cmdlet duplicates a token to another with specified 
.PARAMETER Token
Specify the token to duplicate. If not specified will use the current process token.
.PARAMETER ImpersonationLevel
If specified will duplicate the token as an impersonation token.
.PARAMETER Primary
If specified will duplicate the token as a primary token.
.PARAMETER Access
Specify the access to the new token object.
.PARAMETER Inherit
Specify the token handle is inheritable.
.PARAMETER SecurityDescriptor
Specify the new token's security descriptor.
.INPUTS
None
.OUTPUTS
NtApiDotNet.NtToken
.EXAMPLE
Copy-NtToken -Primary
Copy the current token as a primary token.
.EXAMPLE
Copy-NtToken -ImpersonationLevel Impersonation
Copy the current token as a primary token.
.EXAMPLE
Copy-NtToken -Primary -Token $token
Copy an existing token as a primary token.
#>
function Copy-NtToken {
    [CmdletBinding(DefaultParameterSetName = "Impersonation")]
    Param(
        [NtApiDotNet.NtToken]$Token,
        [parameter(Mandatory, ParameterSetName="Impersonation", Position=0)]
        [NtApiDotNet.SecurityImpersonationLevel]$ImpersonationLevel,
        [parameter(Mandatory, ParameterSetName="Primary")]
        [switch]$Primary,
        [NtApiDotNet.TokenAccessRights]$Access = "MaximumAllowed",
        [switch]$Inherit,
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor
    )

    switch($PSCmdlet.ParameterSetName) {
        "Impersonation" {
            $tokentype = "Impersonation"
        }
        "Primary" {
            $tokentype = "Primary"
            $ImpersonationLevel = "Anonymous"
        }
    }

    if ($null -eq $Token) {
        $Token = Get-NtToken -Primary
    } else {
        $Token = $Token.Duplicate()
    }

    $attributes = "None"
    if ($Inherit) {
        $attributes = "Inherit"
    }

    Use-NtObject($Token) {
        $Token.DuplicateToken($tokentype, $ImpersonationLevel, $Access, $attributes, $SecurityDescriptor)
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
NtApiDotNet.NtObject
.EXAMPLE
Get-NtObjectFromHandle -Handle 0x1234
Get an object from handle 0x1234.
.EXAMPLE
Get-NtObjectFromHandle -Handle 0x1234 -OwnsHandle
Get an object from handle 0x1234 and owns the handle.
#>
function Get-NtObjectFromHandle {
    Param(
        [parameter(Mandatory, Position=0)]
        [IntPtr]$Handle,
        [switch]$OwnsHandle
    )

    $temp_handle = [NtApiDotNet.SafeKernelObjectHandle]::new($Handle, $false)
    [NtApiDotNet.NtType]::GetTypeForHandle($temp_handle, $true).FromHandle($Handle, $OwnsHandle)
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
        foreach($priv in $RequiredPrivilege) {
            if ($priv.ToString() -notin $privs) {
                return $false
            }
        }

        $groups = $token.Groups | ? Enabled
        foreach($group in $RequiredGroup) {
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
        [switch]$TerminateOnDispose
    )

    Set-NtTokenPrivilege SeDebugPrivilege | Out-Null

    Use-NtObject($ps = Get-NtProcess -Access QueryLimitedInformation,CreateProcess `
            -FilterScript { Test-ProcessToken $_ -User $User -RequiredPrivilege $RequiredPrivilege -RequiredGroup $RequiredGroup }) {
        $parent = $ps | Select-Object -First 1
        if ($null -eq $parent) {
            Write-Error "Couldn't find suitable process to spawn a child."
            return
        }
        New-Win32Process -CommandLine $CommandLine -Desktop $Desktop -CreationFlags $CreationFlags -ParentProcess $parent -TerminateOnDispose:$TerminateOnDispose
    }
}

<#
.SYNOPSIS
Get the values from a registry key.
.DESCRIPTION
This cmdlet will get one more values from a registry key.
.PARAMETER Key
The base key to query the values from.
.PARAMETER Name
The name of the value to query. If not specified then returns all values.
.PARAMETER AsString
Output the values as strings.
.INPUTS
NtKeyValue
.EXAMPLE
Get-NtKeyValue $key
Get all values from a key.
.EXAMPLE
Get-NtKeyValue $key -AsString
Get all values from a key as a string.
.EXAMPLE
Get-NtKeyValue $key -Name ""
Get the default value from a key.
.EXAMPLE
Get-NtKeyValue $key -Name MyValue
Get the MyValue value from a key.
#>
function Get-NtKeyValue {
    [CmdletBinding(DefaultParameterSetName="All")]
    Param(
        [parameter(Mandatory, Position=0)]
        [NtApiDotNet.NtKey]$Key,
        [parameter(ParameterSetName="FromName", Position=1)]
        [string]$Name,
        [switch]$AsString
    )
    $values = switch($PSCmdlet.ParameterSetName) {
        "All" {
            $Key.QueryValues()
        }
        "FromName" {
            @($Key.QueryValue($Name))
        }
    }
    if ($AsString) {
        foreach($v in $values) {
            $v.ToString() | Write-Output
        }
    } else {
        $values | Write-Output
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
.INPUTS
None
.OUTPUTS
None or NtApiDotNet.RequestOplockOutputBuffer if using LeaseLevel.
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
        [NtApiDotNet.NtFile]$File,
        [parameter(Mandatory, ParameterSetName = "OplockExclusive")]
        [switch]$Exclusive,
        [parameter(Mandatory, Position = 1, ParameterSetName = "OplockLevel")]
        [NtApiDotNet.OplockRequestLevel]$Level,
        [parameter(Mandatory, ParameterSetName = "OplockLease")]
        [NtApiDotNet.OplockLevelCache]$LeaseLevel
    )

    switch($PSCmdlet.ParameterSetName) {
        "OplockExclusive" {
            $File.OplockExclusive()
        }
        "OplockLevel" {
            $File.RequestOplock($Level)
        }
        "OplockLease" {
            $File.RequestOplockLease($LeaseLevel)
        }
    }
}

<#
.SYNOPSIS
Get a specified information for an object.
.DESCRIPTION
This cmdlet requests specified information through the QueryInformation system call for an object type. It can return the data as a
buffer or a byte array.
.PARAMETER InformationClass
Specify the information class to query.
.PARAMETER Object
Specify the object to query.
.PARAMETER AsBuffer
Specify to return the information as an allocated buffer.
.PARAMETER InitBuffer
Specify a buffer to initialize the query.
.PARAMETER QueryLength
Specify the length of the query buffer if it needs to be fixed.
.INPUTS
None
.OUTPUTS
byte[] or SafeBuffer
.EXAMPLE
Get-NtObjectInformation $p 1
Query information class #1 on object $p as a byte array.
.EXAMPLE
Get-NtObjectInformation $p 1 -AsBuffer
Query information class #1 on object $p as a buffer.
.EXAMPLE
Get-NtObjectInformation $p 1 -QueryLength 1000
Query information class #1 on object $p as a byte array with an initial size of 1000.
#>
function Get-NtObjectInformation {
  Param(
    [parameter(Mandatory, Position = 0)]
    [NtApiDotNet.NtObject]$Object,
    [parameter(Mandatory, Position = 1)]
    [int]$InformationClass,
    [switch]$AsBuffer,
    [byte[]]$InitBuffer,
    [int]$QueryLength
    )
  if ($null -eq $InitBuffer -and $QueryLength -gt 0) {
    $InitBuffer = New-Object byte[] $QueryLength
  }
  if ($AsBuffer) {
    $Object.QueryRawBuffer($InformationClass, $InitBuffer)
  } else {
    $Object.QueryRawBytes($InformationClass, $InitBuffer)
  }
}

<#
.SYNOPSIS
Set a specified information class for an object.
.DESCRIPTION
This cmdlet sets specified information through the SetInformation system call for an object type.
.PARAMETER InformationClass
Specify the information class to set.
.PARAMETER Object
Specify the object to set.
.PARAMETER Buffer
Specify information as a buffer.
.PARAMETER Bytes
Specify information as bytes.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-NtObjectInformation $p 1 [byte[]]@(0, 1, 2, 3)
Set information class #1 on object $p as a byte array.
.EXAMPLE
Set-NtObjectInformation $p 1 $buffer
Set information class #1 on object $p as a buffer.
#>
function Set-NtObjectInformation {
  [CmdletBinding(DefaultParameterSetName="FromBytes")]
  Param(
    [parameter(Mandatory, Position = 0)]
    [NtApiDotNet.NtObject]$Object,
    [parameter(Mandatory, Position = 1)]
    [int]$InformationClass,
    [parameter(Mandatory, Position = 2, ParameterSetName="FromBytes")]
    [byte[]]$Bytes,
    [parameter(Mandatory, Position = 2, ParameterSetName="FromBuffer")]
    [System.Runtime.InteropServices.SafeBuffer]$Buffer
    )

    switch($PsCmdlet.ParameterSetName) {
        "FromBytes" {
            $Object.SetBytes($InformationClass, $Bytes)
        }
        "FromBuffer" {
            $Object.SetBuffer($InformationClass, $Buffer)
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
        } else {
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
    [parameter(Mandatory, ParameterSetName="FromRaw")]
    [int]$RawValue,
    [parameter(Mandatory, ParameterSetName="FromRaw")]
    [NtApiDotNet.ProcessMitigationPolicy]$Policy,
    [parameter(Mandatory, ParameterSetName="FromImageLoad")]
    [NtApiDotNet.ProcessMitigationImageLoadPolicy]$ImageLoad,
    [parameter(Mandatory, ParameterSetName="FromSignature")]
    [NtApiDotNet.ProcessMitigationBinarySignaturePolicy]$Signature,
    [parameter(Mandatory, ParameterSetName="FromSystemCallDisable")]
    [NtApiDotNet.ProcessMitigationSystemCallDisablePolicy]$SystemCallDisable,
    [parameter(Mandatory, ParameterSetName="FromDynamicCode")]
    [NtApiDotNet.ProcessMitigationDynamicCodePolicy]$DynamicCode,
    [parameter(Mandatory, ParameterSetName="FromExtensionPointDisable")]
    [NtApiDotNet.ProcessMitigationExtensionPointDisablePolicy]$ExtensionPointDisable,
    [parameter(Mandatory, ParameterSetName="FromFontDisable")]
    [NtApiDotNet.ProcessMitigationFontDisablePolicy]$FontDisable,
    [parameter(Mandatory, ParameterSetName="FromControlFlowGuard")]
    [NtApiDotNet.ProcessMitigationControlFlowGuardPolicy]$ControlFlowGuard,
    [parameter(Mandatory, ParameterSetName="FromStrictHandleCheck")]
    [NtApiDotNet.ProcessMitigationStrictHandleCheckPolicy]$StrictHandleCheck,
    [parameter(Mandatory, ParameterSetName="FromChildProcess")]
    [NtApiDotNet.ProcessMitigationChildProcessPolicy]$ChildProcess,
    [parameter(Mandatory, ParameterSetName="FromPayloadRestriction")]
    [NtApiDotNet.ProcessMitigationPayloadRestrictionPolicy]$PayloadRestriction,
    [parameter(Mandatory, ParameterSetName="FromSystemCallFilter")]
    [NtApiDotNet.ProcessMitigationSystemCallFilterPolicy]$SystemCallFilter,
    [parameter(Mandatory, ParameterSetName="FromSideChannelIsolation")]
    [NtApiDotNet.ProcessMitigationSideChannelIsolationPolicy]$SideChannelIsolation,
    [parameter(Mandatory, ParameterSetName="FromAslr")]
    [NtApiDotNet.ProcessMitigationAslrPolicy]$Aslr
    )

    BEGIN {
        $Value = 0
        $FromRaw = $false
        switch($PsCmdlet.ParameterSetName) {
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
        }
    }

    PROCESS {
        if ($null -eq $Process) {
            $Process = Get-NtProcess -Current
        }

        if ($FromRaw) {
            $Process.SetRawMitigationPolicy($Policy, $Value)
        } else {
            $Process.SetMitigationPolicy($Policy, $Value)
        }
    }
}

<#
.SYNOPSIS
Get an appcontainer profile for a specified package name.
.DESCRIPTION
This cmdlet gets an appcontainer profile for a specified package name.
.PARAMETER Name
Specify appcontainer name to use for the profile.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.AppContainerProfile
.EXAMPLE
Get-AppContainerProfile
Get appcontainer profiles for all installed packages.
.EXAMPLE
Get-AppContainerProfile -Name Package_aslkjdskjds
Get an appcontainer profile from a package name.
#>
function Get-AppContainerProfile {
    [CmdletBinding(DefaultParameterSetName="All")]
    Param(
        [parameter(ParameterSetName="All")]
        [switch]$AllUsers,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromName", ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string]$Name
    )

    PROCESS {
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                Get-AppxPackage | Select @{Name="Name"; Expression = {"$($_.Name)_$($_.PublisherId)"}} | Get-AppContainerProfile
            }
            "FromName" {
                [NtApiDotNet.Win32.AppContainerProfile]::Open($Name) | Write-Output
            }
        }
    }
}

<#
.SYNOPSIS
Create a new appcontainer profile for a specified package name.
.DESCRIPTION
This cmdlet create a new appcontainer profile for a specified package name. If the profile already exists it'll open it.
.PARAMETER Name
Specify appcontainer name to use for the profile.
.PARAMETER DisplayName
Specify the profile display name.
.PARAMETER Description
Specify the profile description.
.PARAMETER DeleteOnClose
Specify the profile should be deleted when closed.
.PARAMETER TemporaryProfile
Specify to create a temporary profile. Close the profile after use to delete it.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.AppContainerProfile
.EXAMPLE
New-AppContainerProfile -Name Package_aslkjdskjds
Create a new AppContainer profile with a specified name.
.EXAMPLE
Get-AppContainerProfile -TemporaryProfile
Create a new temporary profile.
#>
function New-AppContainerProfile {
    [CmdletBinding(DefaultParameterSetName="FromName")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName="FromName")]
        [string]$Name,
        [parameter(Position = 1, ParameterSetName="FromName")]
        [string]$DisplayName = "DisplayName",
        [parameter(Position = 2, ParameterSetName="FromName")]
        [string]$Description = "Description",
        [parameter(ParameterSetName="FromName")]
        [NtApiDotNet.Sid[]]$Capabilities,
        [parameter(ParameterSetName="FromName")]
        [switch]$DeleteOnClose,
        [parameter(Mandatory, ParameterSetName="FromTemp")]
        [switch]$TemporaryProfile
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromName" {
            $prof = [NtApiDotNet.Win32.AppContainerProfile]::Create($Name, $DisplayName, $Description, $Capabilities)
            if ($null -ne $prof) {
                $prof.DeleteOnClose = $DeleteOnClose
                Write-Output $prof
            }
        }
        "FromTemp" {
            [NtApiDotNet.Win32.AppContainerProfile]::CreateTemporary() | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get a RPC client object based on a parsed RPC server.
.DESCRIPTION
This cmdlet creates a new RPC client from a parsed RPC server. The client object contains methods
to call RPC methods. The client starts off disconnected. You need to pass the client to Connect-RpcClient to
connect to the server. If you specify an interface ID and version then a generic client will be created which 
allows simple calls to be made without requiring the NDR data.
.PARAMETER Server
Specify the RPC server to base the client on.
.PARAMETER NamespaceName
Specify the name of the compiled namespace for the client.
.PARAMETER ClientName
Specify the class name of the compiled client.
.PARAMETER IgnoreCache
Specify to ignore the compiled client cache and regenerate the source code.
.PARAMETER InterfaceId
Specify the interface ID for a generic client.
.PARAMETER InterfaceVersion
Specify the interface version for a generic client.
.PARAMETER Provider
Specify a Code DOM provider. Defaults to C#.
.PARAMETER Flags
Specify optional flags for the built client class.
.PARAMETER EnableDebugging
Specify to enable debugging on the compiled code.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Rpc.RpcClientBase
.EXAMPLE
Get-RpcClient -Server $Server
Create a new RPC client from a parsed RPC server.
#>
function Get-RpcClient {
    [CmdletBinding(DefaultParameterSetName="FromServer")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromServer")]
        [NtApiDotNet.Win32.RpcServer]$Server,
        [parameter(ParameterSetName = "FromServer")]
        [string]$NamespaceName,
        [parameter(ParameterSetName = "FromServer")]
        [string]$ClientName,
        [parameter(ParameterSetName = "FromServer")]
        [switch]$IgnoreCache,
        [parameter(Mandatory, Position=0, ParameterSetName = "FromIdAndVersion")]
        [string]$InterfaceId,
        [parameter(Mandatory, Position=1, ParameterSetName = "FromIdAndVersion")]
        [Version]$InterfaceVersion,
        [parameter(ParameterSetName = "FromServer")]
        [System.CodeDom.Compiler.CodeDomProvider]$Provider,
        [parameter(ParameterSetName = "FromServer")]
        [NtApiDotNet.Win32.Rpc.RpcClientBuilderFlags]$Flags = "GenerateConstructorProperties, StructureReturn, HideWrappedMethods, UnsignedChar, NoNamespace",
        [switch]$EnableDebugging
    )

    if ($PSCmdlet.ParameterSetName -eq "FromServer") {
        $args = [NtApiDotNet.Win32.Rpc.RpcClientBuilderArguments]::new();
        $args.NamespaceName = $NamespaceName
        $args.ClientName = $ClientName
        $args.Flags = $Flags
        $args.EnableDebugging = $EnableDebugging

        [NtApiDotNet.Win32.Rpc.RpcClientBuilder]::CreateClient($Server, $args, $IgnoreCache, $Provider)
    } else {
        [NtApiDotNet.Win32.RpcClient]::new($InterfaceId, $InterfaceVersion)
    }
}

<#
.SYNOPSIS
Connects a RPC client to an endpoint.
.DESCRIPTION
This cmdlet connects a RPC client to an endpoint. You can specify what transport to use based on the protocol sequence.
.PARAMETER Client
Specify the RPC client to connect.
.PARAMETER ProtocolSequence
Specify the RPC protocol sequence this client will connect through.
.PARAMETER EndpointPath
Specify the endpoint string. If not specified this will lookup the endpoint from the endpoint mapper.
.PARAMETER SecurityQualityOfService
Specify the security quality of service for the connection.
.PARAMETER PassThru
Specify to the pass the client object to the output.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Connect-RpcClient -Client $Client
Connect an RPC ALPC client, looking up the path using the endpoint mapper.
.EXAMPLE
Connect-RpcClient -Client $Client -EndpointPath "\RPC Control\ABC"
Connect an RPC ALPC client with an explicit path.
.EXAMPLE
Connect-RpcClient -Client $Client -SecurityQualityOfService $(New-NtSecurityQualityOfService -ImpersonationLevel Anonymous)
Connect an RPC ALPC client with anonymous impersonation level.
.EXAMPLE
Connect-RpcClient -Client $Client -ProtocolSequence "ncalrpc"
Connect an RPC ALPC client from a specific protocol sequence.
.EXAMPLE
Connect-RpcClient -Client $Client -Endpoint $ep
Connect an RPC client to a specific endpoint.
#>
function Connect-RpcClient {
    [CmdletBinding(DefaultParameterSetName="FromProtocol")]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtApiDotNet.Win32.Rpc.RpcClientBase]$Client,
        [parameter(Position = 1, ParameterSetName="FromProtocol")]
        [string]$EndpointPath,
        [parameter(ParameterSetName="FromProtocol")]
        [string]$ProtocolSequence = "ncalrpc",
        [parameter(Position = 1, Mandatory, ParameterSetName="FromEndpoint")]
        [NtApiDotNet.Win32.RpcEndpoint]$Endpoint,
        [NtApiDotNet.SecurityQualityOfService]$SecurityQualityOfService,
        [switch]$PassThru
    )

    if ($PSCmdlet.ParameterSetName -eq "FromProtocol") {
        $Client.Connect($ProtocolSequence, $EndpointPath, $SecurityQualityOfService)
    } else {
        $Client.Connect($Endpoint, $SecurityQualityOfService)
    }
    if ($PassThru) {
        $Client | Write-Output
    }
}

<#
.SYNOPSIS
Format a RPC client as source code based on a parsed RPC server.
.DESCRIPTION
This cmdlet gets source code for a RPC client from a parsed RPC server.
.PARAMETER Server
Specify the RPC server to base the client on.
.PARAMETER NamespaceName
Specify the name of the compiled namespace for the client.
.PARAMETER ClientName
Specify the class name of the compiled client.
.PARAMETER Flags
Specify to flags for the source creation.
.PARAMETER Provider
Specify a Code DOM provider. Defaults to C#.
.PARAMETER Options
Specify optional options for the code generation if Provider is also specified.
.INPUTS
None
.OUTPUTS
string
.EXAMPLE
Format-RpcClient -Server $Server
Get the source code for a RPC client from a parsed RPC server.
.EXAMPLE
$servers | Format-RpcAlpcClient
Get the source code for a RPC client from a list of parsed RPC server.
#>
function Format-RpcClient {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtApiDotNet.Win32.RpcServer[]]$Server,
        [string]$NamespaceName,
        [string]$ClientName,
        [NtApiDotNet.Win32.Rpc.RpcClientBuilderFlags]$Flags = 0,
        [System.CodeDom.Compiler.CodeDomProvider]$Provider,
        [System.CodeDom.Compiler.CodeGeneratorOptions]$Options
    )

    PROCESS {
        $args = [NtApiDotNet.Win32.Rpc.RpcClientBuilderArguments]::new();
        $args.NamespaceName = $NamespaceName
        $args.ClientName = $ClientName
        $args.Flags = $Flags

        foreach($s in $Server) {
            if ($Provider -eq $null) {
                [NtApiDotNet.Win32.Rpc.RpcClientBuilder]::BuildSource($s, $args) | Write-Output
            } else {
                [NtApiDotNet.Win32.Rpc.RpcClientBuilder]::BuildSource($s, $args, $Provider, $Options) | Write-Output
            }
        }
    }
}

<#
.SYNOPSIS
Format RPC complex types to an encoder/decoder source code file.
.DESCRIPTION
This cmdlet gets source code for encoding and decoding RPC complex types.
.PARAMETER ComplexType
Specify the list of complex types to format.
.PARAMETER Server
Specify the server containing the list of complex types to format.
.PARAMETER NamespaceName
Specify the name of the compiled namespace for the client.
.PARAMETER EncoderName
Specify the class name of the encoder.
.PARAMETER DecoderName
Specify the class name of the decoder.
.PARAMETER Provider
Specify a Code DOM provider. Defaults to C#.
.PARAMETER Options
Specify optional options for the code generation if Provider is also specified.
.INPUTS
None
.OUTPUTS
string
.EXAMPLE
Format-RpcComplexType -Server $Server
Get the source code for RPC complex types client from a parsed RPC server.
.EXAMPLE
Format-RpcComplexType -ComplexType $ComplexTypes
Get the source code for RPC complex types client from a list of types.
#>
function Format-RpcComplexType {
    [CmdletBinding(DefaultParameterSetName="FromTypes")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName="FromTypes")]
        [NtApiDotNet.Ndr.NdrComplexTypeReference[]]$ComplexType,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromServer")]
        [NtApiDotNet.Win32.RpcServer]$Server,
        [string]$NamespaceName,
        [string]$EncoderName,
        [string]$DecoderName,
        [NtApiDotNet.Win32.Rpc.RpcClientBuilderFlags]$Flags = 0,
        [System.CodeDom.Compiler.CodeDomProvider]$Provider,
        [System.CodeDom.Compiler.CodeGeneratorOptions]$Options
    )

    PROCESS {
        $types = switch($PsCmdlet.ParameterSetName) {
            "FromTypes" { $ComplexType }
            "FromServer" { $Server.ComplexTypes }
        }
        if ($Provider -eq $null) {
            [NtApiDotNet.Win32.Rpc.RpcClientBuilder]::BuildSource([NtApiDotNet.Ndr.NdrComplexTypeReference[]]$types, $EncoderName, $DecoderName, $NamespaceName) | Write-Output
        } else {
            [NtApiDotNet.Win32.Rpc.RpcClientBuilder]::BuildSource([NtApiDotNet.Ndr.NdrComplexTypeReference[]]$types, $EncoderName, $DecoderName, $NamespaceName, $Provider, $Options) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get a new RPC context handle.
.DESCRIPTION
This cmdlet creates a new RPC context handle for calling RPC APIs.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Ndr.NdrContextHandle
.EXAMPLE
New-RpcContextHandle 
Creates a new RPC context handle.
#>
function New-RpcContextHandle {
    New-Object "NtApiDotNet.Ndr.NdrContextHandle"
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
NtApiDotNet.NtFile
.EXAMPLE
Get-Win32File -Path c:\abc\xyz.txt
Open the existing file c:\abc\xyz.txt
#>
function Get-Win32File {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$Path,
        [NtApiDotNet.FileAccessRights]$DesiredAccess = "MaximumAllowed",
        [NtApiDotNet.FileShareMode]$ShareMode = 0,
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [switch]$InheritHandle,
        [NtApiDotNet.Win32.CreateFileDisposition]$Disposition = "OpenExisting",
        [NtApiDotNet.Win32.CreateFileFlagsAndAttributes]$FlagsAndAttributes = 0,
        [NtApiDotNet.NtFile]$TemplateFile
    )

    [NtApiDotNet.Win32.Win32Utils]::CreateFile($Path, $DesiredAccess, $ShareMode, `
            $SecurityDescriptor, $InheritHandle, $Disposition, $FlagsAndAttributes, $TemplateFile)
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
#>
function Close-NtObject {
    [CmdletBinding(DefaultParameterSetName="FromProcess")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName="FromObject")]
        [NtApiDotNet.NtObject]$Object,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromProcess")]
        [NtApiDotNet.NtProcess]$Process,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromProcessId")]
        [int]$ProcessId,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromProcess")]
        [parameter(Mandatory, Position = 1, ParameterSetName="FromProcessId")]
        [IntPtr]$Handle
    )

    PROCESS {
        switch($PsCmdlet.ParameterSetName) {
            "FromObject" { $Object.Close() }
            "FromProcess" { [NtApiDotNet.NtObject]::CloseHandle($Process, $Handle) }
            "FromProcessId" { [NtApiDotNet.NtObject]::CloseHandle($ProcessId, $Handle) }
        }
    }
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
        [NtObjectManager.ScheduledTaskAccessCheckResult]$Task,
		[string]$User,
		[NtObjectManager.TaskRunFlags]$Flags = 0,
		[int]$SessionId,
		[string[]]$Arguments
    )

	$Task.RunEx($Flags, $SessionId, $User, $Arguments)
}