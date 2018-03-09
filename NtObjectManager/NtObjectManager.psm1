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
This cmdlet will set the integrity level of a token. If you want to raise the level you must have SeTcbPrivilege otherwise you can only lower it. If no token is specified then the current process token is used.
.PARAMETER IntegrityLevel
A list of privileges to set their state.
.PARAMETER Token
Optional token object to use to set privileges. Must be accesible for AdjustDefault right.
.PARAMETER Adjustment
Increment or decrement the IL level from the base specified in -IntegrityLevel.
.INPUTS
None
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
function Set-NtTokenIntegrityLevel
{
  Param(
    [Parameter(Mandatory=$true, Position=0)]
    [NtApiDotNet.TokenIntegrityLevel[]]$IntegrityLevel,
    [NtApiDotNet.NtToken]$Token,
    [Int32]$Adjustment = 0
    )
  if ($Token -eq $null) {
    $Token = Get-NtToken -Primary
  } else {
    $Token = $Token.Duplicate()
  }

  $il_raw = $IntegrityLevel.ToInt32($null) + $Adjustment
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
    [int]$Win32kFilterLevel = 0
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
    -MitigationOptions $MitigationOptions
  }

  if ($null -eq $Token) {
    [NtApiDotNet.Win32.Win32Process]::CreateProcess($config)
  } else {
    [NtApiDotNet.Win32.Win32Process]::CreateProcessAsUser($Token, $config)
  }
}

<#
.SYNOPSIS
Get the NT path for a dos path.
.DESCRIPTION
This cmdlet gets the full NT path for a specified DOS path or multiple.
.PARAMETER Path
The DOS path to convert to NT.
.PARAMETER Resolve
Resolve relative paths to the current PS directory.
.INPUTS
string[] List of paths to convert.
.OUTPUTS
string[] Converted paths.
#>
function Get-NtFilePath {
  [CmdletBinding()]
  Param(
    [parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [string[]]$Path,
    [switch]$Resolve
  )

  PROCESS {
    foreach($path in $Path) {
      $type = [NtApiDotNet.NtFileUtils]::GetDosPathType($path)
      $p = $path
      if ($Resolve) {
        if ($type -eq "Relative" -or $type -eq "Rooted") {
          $p = Resolve-Path -LiteralPath $p
        }
      }
      $p = [NtApiDotNet.NtFileUtils]::DosFileNameToNt($p)
      Write-Output $p
    }
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
    [switch]$Win32Path
  )

  if ($null -eq $File)
  {
    if ($Win32Path)
    {
      $Path = Get-NtFilePath $Path -Resolve
    }
    Use-NtObject($new_file = Get-NtFile -Path $Path -Share Read,Delete -Access GenericExecute) {
      return [NtApiDotNet.NtSection]::CreateImageSection($new_file)
    }
  }
  else
  {
    return [NtApiDotNet.NtSection]::CreateImageSection($File)
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
One or more filenames to get the executable manifest from
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
        [string[]]$Path
    )
    PROCESS {
        foreach($p in $Path)
        {
          $fullpath = Resolve-Path -LiteralPath $p
          $manifest = [NtApiDotNet.Win32.ExecutableManifest]::GetManifests($fullpath)
          Write-Output $manifest
        }
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
    if (!$Object.IsAccessGranted("ReadControl")) {
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
.OUTPUTS
NtApiDotNet.NtIoControlCode
.EXAMPLE
Get-NtIoControlCode 0x22000C
Get the IO control code structure for a control code.
.EXAMPLE
Get-NtIoControlCode -DeviceType NAMED_PIPE -Function 10 -Method Buffered -Access Any
Get the IO control code structure from component parts.
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
    [NtApiDotNet.FileControlAccess]$Access
    )

  switch ($PsCmdlet.ParameterSetName) {
    "FromCode" {
      return [NtApiDotNet.NtIoControlCode]::new($ControlCode)
    }
    "FromParts" {
      return [NtApiDotNet.NtIoControlCode]::new($DeviceType, $Function, $Method, $Access)
    }
  }
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
        [NtApiDotNet.NtToken[]]$Token,
        [Parameter(Mandatory=$true, Position=0, ParameterSetName="FromProcess", ValueFromPipeline=$true)]
        [NtApiDotNet.NtProcess[]]$Process,
        [Parameter(Position=0, ParameterSetName="FromPid")]
        [int]$ProcessId = $pid,
        [Parameter(Mandatory=$true, Position=0, ParameterSetName="FromName")]
        [string]$Name,
        [Parameter(Position=0, ParameterSetName="FromName")]
        [int]$MaxTokens = 0,
        [Parameter(Position=0, ParameterSetName="All")]
        [switch]$All
    )

    PROCESS {
      if (-not $(Test-Path "$PSScriptRoot\TokenViewer.exe" -PathType Leaf)) {
        Write-Error "Missing token viewer application $PSScriptRoot\TokenViewer.exe"
        return
      }
      switch($PSCmdlet.ParameterSetName) {
        "FromProcess" {
          foreach($p in $Process) {
            Use-NtObject($t = Get-NtToken -Primary -Process $p) {
              $text = "$($p.Name):$($p.ProcessId)"
              Start-NtTokenViewer $t -Text $text
            }
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
          foreach($t in $Token) {
            Start-NtTokenViewer $t
          }
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
#>
function Show-NtSection {
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [NtApiDotNet.NtSection]$Section,
        [switch]$ReadOnly,
        [switch]$Wait
    )

  if (!$Section.IsAccessGranted("MapRead")) {
    Write-Error "Section doesn't have Map Read access."
    return
  }
  Use-NtObject($obj = $Section.Duplicate()) {
    $obj.Inherit = $true
    $cmdline = [string]::Format("EditSection {0}", $obj.Handle.DangerousGetHandle())
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
Resolve-NtObjectAddress @($obj1, $obj2); $obj1.Address
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
