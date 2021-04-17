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
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.DirectoryService.DirectoryServiceExtendedRight[]
.EXAMPLE
Get-DsExtendedRight
Get all extended rights.
.EXAMPLE
Get-DsExtendedRight -RightId "e48d0154-bcf8-11d1-8702-00c04fb96050"
Get get the Public-Information extended right by GUID.
#>
function Get-DsExtendedRight {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(ParameterSetName = "FromGuid")]
        [guid]$RightId
    )

    switch ($PSCmdlet.ParameterSetName) {
        "All" {
            [NtApiDotNet.Win32.DirectoryService.DirectoryServiceUtils]::GetExtendedRights() | Write-Output
        }
        "FromGuid" {
            [NtApiDotNet.Win32.DirectoryService.DirectoryServiceUtils]::GetExtendedRight($RightId)
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
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.DirectoryService.DirectoryServiceSchemaClass[]
.EXAMPLE
Get-DsSchemaClass
Get all schema classes.
.EXAMPLE
Get-DsSchemaClass -SchemaId "BF967ABA-0DE6-11D0-A285-00AA003049E2"
Get get the user schema class by GUID.
#>
function Get-DsSchemaClass {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(ParameterSetName = "FromGuid")]
        [guid]$SchemaId
    )

    switch ($PSCmdlet.ParameterSetName) {
        "All" {
            [NtApiDotNet.Win32.DirectoryService.DirectoryServiceUtils]::GetSchemaClasses() | Write-Output
        }
        "FromGuid" {
            [NtApiDotNet.Win32.DirectoryService.DirectoryServiceUtils]::GetSchemaClass($SchemaId)
        }
    }
}