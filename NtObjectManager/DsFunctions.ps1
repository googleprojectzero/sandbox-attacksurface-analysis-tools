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
Get an extended right from the local Active Directory.
.DESCRIPTION
This cmdlet gets an extended right from the local Active Directory. This can be slow.
.PARAMETER RightId
Specify the GUID for the right.
.PARAMETER Domain
Specify the domain or server name to query for the extended rights. Defaults to current domain.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.DirectoryService.DirectoryServiceExtendedRight[]
.EXAMPLE
Get-DsExtendedRight
Get all extended rights.
.EXAMPLE
Get-DsExtendedRight -Domain sales.domain.com
Get all extended rights on the sales.domain.com domain.
.EXAMPLE
Get-DsExtendedRight -RightId "e48d0154-bcf8-11d1-8702-00c04fb96050"
Get get the Public-Information extended right by GUID.
#>
function Get-DsExtendedRight {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromGuid", Position = 0)]
        [guid]$RightId,
        [string]$Domain
    )

    switch ($PSCmdlet.ParameterSetName) {
        "All" {
            [NtApiDotNet.Win32.DirectoryService.DirectoryServiceUtils]::GetExtendedRights($Domain) | Write-Output
        }
        "FromGuid" {
            [NtApiDotNet.Win32.DirectoryService.DirectoryServiceUtils]::GetExtendedRight($Domain, $RightId)
        }
    }
}

<#
.SYNOPSIS
Get a schema class from the local Active Directory.
.DESCRIPTION
This cmdlet gets a schema class from the local Active Directory. This can be slow.
.PARAMETER SchemaId
Specify the GUID for the schema class.
.PARAMETER Domain
Specify the domain or server name to query for the schema class. Defaults to current domain.
.PARAMETER Name
Specify the LDAP name for the schema class to get.
.PARAMETER Parent
Specify an existing schema class and get its parent class.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.DirectoryService.DirectoryServiceSchemaClass[]
.EXAMPLE
Get-DsSchemaClass
Get all schema classes.
.EXAMPLE
Get-DsSchemaClass -Domain sales.domain.com
Get all schema classes on the sales.domain.com domain.
.EXAMPLE
Get-DsSchemaClass -SchemaId "BF967ABA-0DE6-11D0-A285-00AA003049E2"
Get the user schema class by GUID.
.EXAMPLE
Get-DsSchemaClass -Name User
Get the user schema class by LDAP name.
.EXAMPLE
Get-DsSchemaClass -Parent $cls
Get the parent schema class for another class.
#>
function Get-DsSchemaClass {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromGuid")]
        [guid]$SchemaId,
        [parameter(Mandatory, ParameterSetName = "FromName", Position = 0)]
        [string]$Name,
        [parameter(Mandatory, ParameterSetName = "FromParent", Position = 0)]
        [NtApiDotNet.Win32.DirectoryService.DirectoryServiceSchemaClass]$Parent,
        [string]$Domain
    )

    switch ($PSCmdlet.ParameterSetName) {
        "All" {
            [NtApiDotNet.Win32.DirectoryService.DirectoryServiceUtils]::GetSchemaClasses($Domain) | Write-Output
        }
        "FromGuid" {
            [NtApiDotNet.Win32.DirectoryService.DirectoryServiceUtils]::GetSchemaClass($Domain, $SchemaId)
        }
        "FromName" {
            [NtApiDotNet.Win32.DirectoryService.DirectoryServiceUtils]::GetSchemaClass($Domain, $Name)
        }
        "FromParent" {
            if (($null -ne $Parent.SubClassOf) -and ($Parent.SubClassOf -ne $Parent.Name)) {
                Get-DsSchemaClass -Domain $Domain -Name $Parent.SubClassOf
            }
        }
    }
}