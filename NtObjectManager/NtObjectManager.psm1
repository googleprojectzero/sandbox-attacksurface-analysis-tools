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
function Get-AccessibleAlpcPort
{
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
  if ($Token -eq $null) {
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
This cmdlet will get the mitigation policies for all processes it can access for QueryInformation rights.
#>
function Get-NtProcessMitigations
{
  Set-NtTokenPrivilege SeDebugPrivilege | Out-Null
  Use-NtObject($ps = Get-NtProcess -Access QueryInformation) {
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
  if ($Sddl -ne $null)
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
    [NtApiDotNet.Win32.ProtectionLevel]$ProtectionLevel = "WindowsPPL"
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
.PARAMETER Token
Specify an explicit token to create the new process with.
.PARAMETER Config
Specify the configuration for the new process.
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
    [Parameter(Mandatory=$true, Position=0, ParameterSetName = "FromConfig")]
    [NtApiDotNet.Win32.Win32ProcessConfig]$Config
    )

  if ($null -eq $Config) {
    $Config = New-Win32ProcessConfig $CommandLine -ApplicationName $ApplicationName `
    -ProcessSecurityDescriptor $ProcessSecurityDescriptor -ThreadSecurityDescriptor $ThreadSecurityDescriptor `
    -ParentProcess $ParentProcess -CreationFlags $CreationFlags -TerminateOnDispose:$TerminateOnDispose `
    -Environment $Environment -CurrentDirectory $CurrentDirectory -Desktop $Desktop -Title $Title `
    -InheritHandles:$InheritHandles -InheritProcessHandle:$InheritProcessHandle -InheritThreadHandle:$InheritThreadHandle `
    -MitigationOptions $MitigationOptions -Token $Token
  }

  [NtApiDotNet.Win32.Win32Process]::CreateProcess($config)
}

<#
.SYNOPSIS
Get the NT path for a dos path.
.DESCRIPTION
This cmdlet gets the full NT path for a specified DOS path.
.PARAMETER Path
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
Get-ChildItem c:\windows | Get-NtFilePath
Get list of NT file paths from the pipeline.
#>
function Get-NtFilePath {
  [CmdletBinding()]
  Param(
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
    $p = [NtApiDotNet.NtFileUtils]::DosFileNameToNt($p)
    Write-Output $p
  }
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

  if ($Object -ne $null) {
    if (!$Object.IsAccessMaskGranted([NtApiDotNet.GenericAccessRights]::ReadControl)) {
      Write-Error "Object doesn't have Read Control access."
      return
    }
    Use-NtObject($obj = $Object.Duplicate()) {
      $obj.Inherit = $true
      $cmdline = [string]::Format("ViewSecurityDescriptor {0}", $obj.Handle.DangerousGetHandle())
      if ($ReadOnly) {
        $cmdline += " --readonly"
      }
      $config = New-Win32ProcessConfig $cmdline -ApplicationName "$PSScriptRoot\ViewSecurityDescriptor.exe" -InheritHandles
      $config.InheritHandleList.Add($obj.Handle.DangerousGetHandle())
      Use-NtObject($p = New-Win32Process -Config $config) {
        if ($Wait) {
          $p.Process.Wait() | Out-Null
        }
      }
    }
  } else {
    Start-Process -FilePath "$PSScriptRoot\ViewSecurityDescriptor.exe" -ArgumentList @($Name,$SecurityDescriptor.ToSddl(),$Type.Name) -Wait:$Wait
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
    [switch]$LookupName
    )
  $control_code = switch ($PsCmdlet.ParameterSetName) {
    "FromCode" {
      [NtApiDotNet.NtIoControlCode]::new($ControlCode)
    }
    "FromParts" {
      [NtApiDotNet.NtIoControlCode]::new($DeviceType, $Function, $Method, $Access)
    }
  }

  if ($LookupName) {
    return [NtApiDotNet.NtWellKnownIoControlCodes]::KnownControlCodeToName($control_code)
  }
  $control_code
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
duplicated between PowerShell instances.
.PARAMETER Object
Specify the object to import as a JSON string.
.OUTPUTS
NtApiDotNet.NtObject
.EXAMPLE
Import-NtObject '{"ProcessId":3300,"Handle":2660}'
Import an object from a JSON string.
#>
function Import-NtObject {
    param(
    [Parameter(Position = 0, Mandatory = $true)]
    [string]$Object
  )
    $obj = ConvertFrom-Json $Object
    Use-NtObject($generic = [NtApiDotNet.NtGeneric]::DuplicateFrom($obj.ProcessId, $obj.Handle)) {
        $generic.ToTypedObject()
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
        $file.GetReparsePoint($true)
    }
}

<#
.SYNOPSIS
Creates a new execution alias information.
.DESCRIPTION
This cmdlet creates a new execution alias for a packaged application.
.PARAMETER PackageName
The name of the UWP package.
.PARAMETER EntryPoint
The entry point of the application
.PARAMETER Target
The target executable path
.PARAMETER Flags
Additional flags
.PARAMETER Version
Version number
.EXAMPLE
Set-ExecutionAlias c:\path\to\alias.exe -PackageName test -EntryPoint test!test -Target c:\test.exe -Flags 48 -Version 3
Set the alias.exe execution alias.
#>
function New-ExecutionAlias
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
        [Int32]$Flags = 48,
        [Int32]$Version = 3
    )

    $rp = [NtApiDotNet.ExecutionAliasReparseBuffer]::new($Version, $PackageName, $EntryPoint, $Target, $Flags)
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
        [parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true, ParameterSetName = "FromObject")]
        [NtApiDotNet.NtObject]$Object,
        [parameter(Position=1, ParameterSetName = "FromObject")]
        [NtApiDotNet.SecurityInformation]$SecurityInformation = "AllBasic",
        [parameter(Mandatory = $true, ParameterSetName = "FromProcess")]
        [NtApiDotNet.NtProcess]$Process,
        [parameter(Mandatory = $true, ParameterSetName = "FromProcess")]
        [int64]$Address,
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
The object to get the security descriptor from.
.PARAMETER SecurityInformation
The security information to get from the object.
.PARAMETER ToSddl
Convert the security descriptor to an SDDL string.
.OUTPUTS
NtApiDotNet.SecurityDescriptor
string
.EXAMPLE
Set-NtSecurityDescriptor $obj $sd Dacl
Set the DACL of an object.
.EXAMPLE
Set-NtSecurityDescriptor $obj "D:(A;;GA;;;WD)" Dacl
Set the DACL of an object based on an SDDL string.
#>
function Set-NtSecurityDescriptor
{
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [NtApiDotNet.NtObject]$Object,
        [parameter(Mandatory=$true, Position=1, ParameterSetName = "FromSD")]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [parameter(Mandatory=$true, Position=1, ParameterSetName = "FromSddl")]
        [string]$Sddl,
        [parameter(Mandatory=$true, Position=2)]
        [NtApiDotNet.SecurityInformation]$SecurityInformation
        
    )
    BEGIN {
        switch($PSCmdlet.ParameterSetName) {
            "FromSD" {
                $sd = $SecurityDescriptor
            }
            "FromSddl" {
                $sd = New-NtSecurityDescriptor -Sddl $Sddl
            }
        }
    }
    PROCESS {
        $Object.SetSecurityDescriptor($sd, $SecurityInformation)
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
    $DbgHelpPath = "dbghelp.dll"
  }
  if ($SymbolPath -eq "") {
    $SymbolPath = $env:_NT_SYMBOL_PATH
    if ($SymbolPath -eq "") {
      $SymbolPath = 'srv*https://msdl.microsoft.com/download/symbols'
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
        [NtApiDotNet.Win32.ISymbolResolver]$SymbolResolver
    )
    [NtApiDotNet.Ndr.NdrParser]::new($Process, $SymbolResolver)
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
.OUTPUTS
The parsed proxy information and complex types.
.EXAMPLE
$p = Get-NdrComProxy c:\path\to\proxy.dll
Parse the proxy information from c:\path\to\proxy.dll
.EXAMPLE
$p = Get-NdrComProxy $env:SystemRoot\system32\combase.dll -Clsid "00000320-0000-0000-C000-000000000046"
Parse the proxy information from combase.dll with a specific proxy CLSID.
#>
function Get-NdrComProxy {
    Param(
        [parameter(Mandatory, Position=0)]
        [string]$Path,
        [Guid]$Clsid = [Guid]::Empty,
        [NtApiDotNet.Win32.ISymbolResolver]$SymbolResolver
    )
    $Path = Resolve-Path $Path -ErrorAction Stop
    Use-NtObject($parser = New-NdrParser -SymbolResolver $SymbolResolver) {
        $proxies = $parser.ReadFromComProxyFile($Path, $Clsid)
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
$ndr.ComplexTypes = | Format-NdrComplexType
Format a list of complex types from a pipeline.
.EXAMPLE
Format-NdrComplexType $type -IidToName @{"00000000-0000-0000-C000-000000000046"="IUnknown";}
Format a complex type with a known IID to name mapping.
#>
function Format-NdrComplexType {
  [CmdletBinding()]
    Param(
    [parameter(Mandatory, Position=0, ValueFromPipeline)]
    [NtApiDotNet.Ndr.NdrComplexTypeReference]$ComplexType,
    [Hashtable]$IidToName
    )

  BEGIN {
    $dict = Convert-HashTableToIidNames($IidToName)
    $formatter = [NtApiDotNet.Ndr.DefaultNdrFormatter]::Create($dict)
  }

  PROCESS {
    $fmt = $formatter.FormatComplexType($ComplexType)
    Write-Output $fmt
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
        [NtApiDotNet.Win32.ISymbolResolver]$SymbolResolver
    )
    $Path = Resolve-Path $Path -ErrorAction Stop
    Use-NtObject($parser = New-NdrParser -SymbolResolver $SymbolResolver) {
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
Get a filtered token.
.DESCRIPTION
This is left for backwards compatibility, use 'Get-NtToken -Filtered' instead.
#>
function Get-NtFilteredToken
{
    Param(
       [parameter(Mandatory=$true, Position=0)]
       [NtApiDotNet.NtToken]$Token,
       [NtApiDotNet.TokenPrivilege[]]$PrivilegesToDelete,
       [NtApiDotNet.UserGroup[]]$SidsToDisable,
       [NtApiDotNet.UserGroup[]]$RestrictedSids,
       [NtApiDotNet.FilterTokenFlags]$Flags
    )

    Write-Warning "This cmdlet is deprecated. Please use Get-NtToken -Filtered instead"
    Get-NtToken -Filtered -Token $Token -PrivilegesToDelete $PrivilegesToDelete -SidsToDisable $SidsToDisable -RestrictedSids $RestrictedSids -Flags $Flags
}

<#
.SYNOPSIS
Get a lowbox token.
.DESCRIPTION
This is left for backwards compatibility, use 'Get-NtToken -LowBox' instead.
#>
function Get-NtLowBoxToken
{
    Param(
       [parameter(Mandatory=$true, Position=0)]
       [NtApiDotNet.NtToken]$Token,
       [parameter(Mandatory=$true)]
       [string]$PackageSid,
       [string]$RestrictedPackageName,
       [NtApiDotNet.Sid[]]$CapabilitySids,
       [NtApiDotNet.NtObject[]]$Handles
    )

    Write-Warning "This cmdlet is deprecated. Please use Get-NtToken -LowBox instead"
    Get-NtToken -LowBox -Token $Token -PackageSid $PackageSid -RestrictedPackageName $RestrictedPackageName -CapabilitySids $CapabilitySids -Handles $Handles
}