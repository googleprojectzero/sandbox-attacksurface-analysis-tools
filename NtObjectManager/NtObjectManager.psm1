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
