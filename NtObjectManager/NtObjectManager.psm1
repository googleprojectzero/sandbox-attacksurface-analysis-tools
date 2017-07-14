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
