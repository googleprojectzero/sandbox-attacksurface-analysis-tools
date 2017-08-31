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

Import-Module "$PSScriptRoot\NtObjectManager.dll"

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
SandboxAnalysisUtils.Win32ProcessConfig
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
		[SandboxAnalysisUtils.CreateProcessFlags]$CreationFlags = 0,
		[SandboxAnalysisUtils.ProcessMitigationOptions]$MitigationOptions = 0,
		[bool]$TerminateOnDispose,
		[byte[]]$Environment,
		[string]$CurrentDirectory,
		[string]$Desktop,
		[string]$Title,
		[bool]$InheritHandles,
		[bool]$InheritProcessHandle,
		[bool]$InheritThreadHandle,
		[SandboxAnalysisUtils.Win32kFilterFlags]$Win32kFilterFlags = 0,
		[int]$Win32kFilterLevel = 0
    )
    $config = New-Object SandboxAnalysisUtils.Win32ProcessConfig
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
SandboxAnalysisUtils.Win32Process
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
		[SandboxAnalysisUtils.CreateProcessFlags]$CreationFlags = 0,
		[Parameter(ParameterSetName = "FromArgs")]
		[SandboxAnalysisUtils.ProcessMitigationOptions]$MitigationOptions = 0,
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
		[SandboxAnalysisUtils.Win32ProcessConfig]$Config
    )

	if ($null -eq $Config) {
		$Config = New-Win32ProcessConfig $CommandLine -ApplicationName $ApplicationName `
		-ProcessSecurityDescriptor $ProcessSecurityDescriptor -ThreadSecurityDescriptor $ThreadSecurityDescriptor `
		-ParentProcess $ParentProcess -CreationFlags $CreationFlags -TerminateOnDispose $TerminateOnDispose `
		-Environment $Environment -CurrentDirectory $CurrentDirectory -Desktop $Desktop -Title $Title `
		-InheritHandles $InheritHandles -InheritProcessHandle $InheritProcessHandle -InheritThreadHandle $InheritThreadHandle `
		-MitigationOptions $MitigationOptions
	}

	if ($null -eq $Token) {
		[SandboxAnalysisUtils.Win32Process]::CreateProcess($config)
	} else {
		[SandboxAnalysisUtils.Win32Process]::CreateProcessAsUser($Token, $config)
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
SandboxAnalysisUtils.ExecutableManifest
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
			$manifest = [SandboxAnalysisUtils.ExecutableManifest]::GetManifests($fullpath)
			Write-Output $manifest
		}
    }
}

<#
.SYNOPSIS
Get process primary token. Here for legacy reasons, use Get-NtToken -Primary.
#>
function Get-NtTokenPrimary
{
	Get-NtToken -Primary @args
}

<#
.SYNOPSIS
Get thread impersonation token. Here for legacy reasons, use Get-NtToken -Impersonation.
#>
function Get-NtTokenThread
{
	Get-NtToken -Impersonation @args
}

<#
.SYNOPSIS
Get thread effective token. Here for legacy reasons, use Get-NtToken -Effective.
#>
function Get-NtTokenEffective
{
	Get-NtToken -Effective @args
}
