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
Get a list of ALPC Ports that can be opened by a specificed token.
.DESCRIPTION
This cmdlet checks for all ALPC ports on the system and tries to determine if one or more specified tokens can connect to them. 
If no token are specified then the current process token is used. This function searches handles for existing ALPC Port servers as you can't directly open the server object and just connecting might show inconsistent results.
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
		[NtApiDotNet.NtToken[]]$Tokens
		)
	# Access0 is Connect for ALPC Ports.
	Get-AccessibleObject -FromHandles -ProcessIds $ProcessIds -ProcessNames $ProcessNames `
		-ProcessCommandLines $ProcessCommandLines -Tokens $Tokens -TypeFilter "ALPC Port" -AccessRights Access0 
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
