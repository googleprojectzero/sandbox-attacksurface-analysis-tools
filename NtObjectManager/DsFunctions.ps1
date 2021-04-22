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
Get an extended right from Active Directory.
.DESCRIPTION
This cmdlet gets an extended right from Active Directory. This can be slow.
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
Get a schema class from Active Directory.
.DESCRIPTION
This cmdlet gets a schema class from Active Directory. This can be slow.
.PARAMETER SchemaId
Specify the GUID for the schema class.
.PARAMETER Domain
Specify the domain or server name to query for the schema class. Defaults to current domain.
.PARAMETER Name
Specify the LDAP name for the schema class to get.
.PARAMETER Parent
Specify an existing schema class and get its parent class.
.PARAMETER Recurse
Specify to recurse the parent relationships and return all objects.
.PARAMETER Attribute
Specify to get the schema class for an attribute.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.DirectoryService.DirectoryServiceSchemaObject[]
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
        [parameter(ParameterSetName = "All")]
        [parameter(ParameterSetName = "FromName")]
        [parameter(ParameterSetName = "FromGuid")]
        [parameter(ParameterSetName = "FromAttribute")]
        [string]$Domain,
        [parameter(ParameterSetName = "FromParent")]
        [parameter(ParameterSetName = "FromName")]
        [parameter(ParameterSetName = "FromGuid")]
        [switch]$Recurse,
        [parameter(Mandatory, ParameterSetName = "FromAttribute", ValueFromPipeline)]
        [NtApiDotNet.Win32.DirectoryService.DirectoryServiceSchemaClassAttribute]$Attribute
    )

    PROCESS {
        $cls = switch ($PSCmdlet.ParameterSetName) {
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
                if (("" -ne $Parent.SubClassOf) -and ($Parent.SubClassOf -ne $Parent.Name)) {
                    Get-DsSchemaClass -Domain $Parent.Domain -Name $Parent.SubClassOf
                }
            }
            "FromAttribute" {
                [NtApiDotNet.Win32.DirectoryService.DirectoryServiceUtils]::GetSchemaClass($Domain, $Attribute.Name)
            }
        }
        $cls
        if ($Recurse -and $cls -is [NtApiDotNet.Win32.DirectoryService.DirectoryServiceSchemaClass]) {
            Get-DsSchemaClass -Parent $cls -Recurse
        }
    }
}

<#
.SYNOPSIS
Get the SID for an object from Active Directory.
.DESCRIPTION
This cmdlet gets the SID for an object from Active Directory. This can be slow.
.PARAMETER DistinguishedName
Specify the distinguished name of the object.
.PARAMETER Object
Specify the object directory entry.
.PARAMETER Domain
Specify the domain or server name to query for the object. Defaults to current domain.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Sid
.EXAMPLE
Get-DsObjectSid -DistinguishedName "CN=Bob,CN=Users,DC=domain,DC=com"
Get the object SID for a user object by name.
.EXAMPLE
Get-DsObjectSid -DistinguishedName "CN=Bob,CN=Users,DC=sales,DC=domain,DC=com" -Domain SALES
Get the object SID for a user object by name in the SALES domain.
.EXAMPLE
Get-DsObjectSid -Object $obj
Get the object SID from a user object.
#>
function Get-DsObjectSid {
    [CmdletBinding(DefaultParameterSetName = "FromName")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromName", Position = 0)]
        [alias("dn")]
        [string]$DistinguishedName,
        [parameter(ParameterSetName = "FromName")]
        [string]$Domain,
        [parameter(Mandatory, ParameterSetName = "FromObject")]
        [System.DirectoryServices.DirectoryEntry]$Object
    )

    switch ($PSCmdlet.ParameterSetName) {
        "FromName" {
            [NtApiDotNet.Win32.DirectoryService.DirectoryServiceUtils]::GetObjectSid($Domain, $DistinguishedName)
        }
        "FromObject" {
            [NtApiDotNet.Win32.DirectoryService.DirectoryServiceUtils]::GetObjectSid($Object)
        }
    }
}

<#
.SYNOPSIS
Get the schema class for an object from Active Directory.
.DESCRIPTION
This cmdlet gets the schema class for an object from Active Directory. This can be slow.
.PARAMETER DistinguishedName
Specify the distinguished name of the object.
.PARAMETER Object
Specify the object directory entry.
.PARAMETER Domain
Specify the domain or server name to query for the object. Defaults to current domain.
.PARAMETER Recurse
Specify to get all schema classes for the object in the inheritance chain.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.DirectoryService.DirectoryServiceSchemaClass[]
.EXAMPLE
Get-DsObjectSchemaClass -DistinguishedName "CN=Bob,CN=Users,DC=domain,DC=com"
Get the schema class for a user object by name.
.EXAMPLE
Get-DsObjectSchemaClass -DistinguishedName "CN=Bob,CN=Users,DC=sales,DC=domain,DC=com" -Domain SALES
Get the schema class for a user object by name in the SALES domain.
.EXAMPLE
Get-DsObjectSchemaClass -Object $obj
Get the schema class from a user object.
.EXAMPLE
Get-DsObjectSchemaClass -DistinguishedName "CN=Bob,CN=Users,DC=domain,DC=com" -Recurse
Get the all inherited schema class for a user object by name.
#>
function Get-DsObjectSchemaClass {
    [CmdletBinding(DefaultParameterSetName = "FromName")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromName", Position = 0)]
        [alias("dn")]
        [string]$DistinguishedName,
        [parameter(ParameterSetName = "FromName")]
        [string]$Domain,
        [parameter(Mandatory, ParameterSetName = "FromObject")]
        [System.DirectoryServices.DirectoryEntry]$Object,
        [switch]$Recurse
    )

    if ($PSCmdlet.ParameterSetName -eq "FromName") {
        $Object = [NtApiDotNet.Win32.DirectoryService.DirectoryServiceUtils]::GetObject($Domain, $DistinguishedName)
    }

    $obj_class = $Object.objectClass
    if ($obj_class.Count -eq 0) {
        return
    }

    Get-DsSchemaClass -Name $obj_class[-1] -Recurse:$Recurse
}

<#
.SYNOPSIS
Converts a DS object to an object type tree for access checking.
.DESCRIPTION
This cmdlet converts a DS object to an object type tree for access checking. This can be slow.
.PARAMETER DistinguishedName
Specify the distinguished name of the object.
.PARAMETER Object
Specify the object directory entry.
.PARAMETER Domain
Specify the domain or server name to query for the object. Defaults to current domain.
.PARAMETER TreeObject
Specify an object convertable to the tree such as a schema object or extended right.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Utilities.Security.ObjectTypeTree
.EXAMPLE
ConvertTo-ObjectTypeTree -DistinguishedName "CN=Bob,CN=Users,DC=domain,DC=com"
Get the object type tree for a user object by name.
#>
function ConvertTo-ObjectTypeTree {
    [CmdletBinding(DefaultParameterSetName = "FromName")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromName", Position = 0)]
        [alias("dn")]
        [string]$DistinguishedName,
        [parameter(ParameterSetName = "FromName")]
        [string]$Domain,
        [parameter(Mandatory, ParameterSetName = "FromObject")]
        [System.DirectoryServices.DirectoryEntry]$Object,
        [parameter(Mandatory, ParameterSetName = "FromTreeObject", ValueFromPipeline)]
        [NtApiDotNet.Win32.DirectoryService.IDirectoryServiceObjectTree]$TreeObject
    )

    PROCESS {
        $tree_obj = switch($PSCmdlet.ParameterSetName) {
            "FromName" {
               Get-DsSchemaClass -Domain $Domain -DistinguishedName $DistinguishedName
            }
            "FromObject" {
                Get-DsSchemaClass -Object $Object
            }
            "FromTreeObject" {
                $TreeObject
            }
        }
        $tree_obj.ToObjectTypeTree()
    }
}