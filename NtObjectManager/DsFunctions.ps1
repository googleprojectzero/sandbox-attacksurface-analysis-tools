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
.PARAMETER Attribute
Specify to get the propert set right for an attribute which is a property.
.PARAMETER Domain
Specify the domain or server name to query for the extended rights. Defaults to current domain.
.PARAMETER Name
Specify the common name of the extended right to get.
.PARAMETER SchemaClass
Specify a schema class to get extended rights.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.DirectoryService.DirectoryServiceExtendedRight[]
.EXAMPLE
Get-DsExtendedRight
Get all extended rights.
.EXAMPLE
Get-DsExtendedRight -Domain sales.domain.com
Get all extended rights on the sales.domain.com domain.
.EXAMPLE
Get-DsExtendedRight -RightId "e48d0154-bcf8-11d1-8702-00c04fb96050"
Get the Public-Information extended right by GUID.
.EXAMPLE
Get-DsExtendedRight -Attribute $attr
Get the property set for the attribute.
#>
function Get-DsExtendedRight {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromGuid", Position = 0)]
        [guid]$RightId,
        [parameter(Mandatory, ParameterSetName = "FromName")]
        [string]$Name,
        [parameter(Mandatory, ParameterSetName = "FromAttribute")]
        [NtCoreLib.Win32.DirectoryService.DirectoryServiceSchemaAttribute]$Attribute,
        [parameter(Mandatory, ParameterSetName = "FromSchemaClass")]
        [NtCoreLib.Win32.DirectoryService.DirectoryServiceSchemaClass]$SchemaClass,
        [parameter(ParameterSetName = "FromSchemaClass")]
        [parameter(ParameterSetName = "FromGuid")]
        [parameter(ParameterSetName = "FromName")]
        [parameter(ParameterSetName = "All")]
        [string]$Domain
    )

    switch ($PSCmdlet.ParameterSetName) {
        "All" {
            [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetExtendedRights($Domain) | Write-Output
        }
        "FromGuid" {
            [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetExtendedRight($Domain, $RightId)
        }
        "FromName" {
            [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetExtendedRight($Domain, $Name)
        }
        "FromSchemaClass" {
            [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetExtendedRights($Domain, $SchemaClass.SchemaId)
        }
        "FromAttribute" {
            if ($null -ne $Attribute.AttributeSecurityGuid) {
                [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetExtendedRight($Attribute.Domain, $Attribute.AttributeSecurityGuid)
            }
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
.PARAMETER Inferior
Specify to return inferior classes which can be created underneath this class.
.PARAMETER IncludeAuxiliary
Specify to return include auxiliary classes with the class.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.DirectoryService.DirectoryServiceSchemaClass[]
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
Get-DsSchemaClass -Name "user"
Get the user schema class by LDAP name.
.EXAMPLE
Get-DsSchemaClass -Name "user" -IncludeAuxiliary
Get the user schema class by LDAP name and include all auxiliary classes.
.EXAMPLE
Get-DsSchemaClass -Parent $cls
Get the parent schema class for another class.
.EXAMPLE
Get-DsSchemaClass -Parent $cls -Recurse
Get the parent schema class for another class and recurse to top.
#>
function Get-DsSchemaClass {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromGuid")]
        [guid]$SchemaId,
        [parameter(Mandatory, ParameterSetName = "FromName", Position = 0, ValueFromPipelineByPropertyName)]
        [string]$Name,
        [parameter(Mandatory, ParameterSetName = "FromParent", Position = 0)]
        [NtCoreLib.Win32.DirectoryService.DirectoryServiceSchemaClass]$Parent,
        [parameter(ParameterSetName = "All")]
        [parameter(ParameterSetName = "FromName")]
        [parameter(ParameterSetName = "FromGuid")]
        [string]$Domain,
        [parameter(ParameterSetName = "FromParent")]
        [parameter(ParameterSetName = "FromName")]
        [parameter(ParameterSetName = "FromGuid")]
        [switch]$Recurse,
        [parameter(ParameterSetName = "FromParent")]
        [parameter(ParameterSetName = "FromName")]
        [parameter(ParameterSetName = "FromGuid")]
        [switch]$Inferior,
        [parameter(ParameterSetName = "FromParent")]
        [parameter(ParameterSetName = "FromName")]
        [parameter(ParameterSetName = "FromGuid")]
        [switch]$IncludeAuxiliary
    )

    PROCESS {
        $cls = switch ($PSCmdlet.ParameterSetName) {
            "All" {
                [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetSchemaClasses($Domain) | Write-Output
            }
            "FromGuid" {
                [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetSchemaClass($Domain, $SchemaId)
            }
            "FromName" {
                [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetSchemaClass($Domain, $Name)
            }
            "FromParent" {
                if (("" -ne $Parent.SubClassOf) -and ($Parent.SubClassOf -ne $Parent.Name)) {
                    Get-DsSchemaClass -Domain $Parent.Domain -Name $Parent.SubClassOf
                }
            }
        }

        if ($null -eq $cls) {
            return
        }

        if ($Inferior) {
            $cls.PossibleInferiors | ForEach-Object { Get-DsSchemaClass -Domain $Domain -Name $_ -IncludeAuxiliary:$IncludeAuxiliary }
        } else {
            $cls
            if ($IncludeAuxiliary) {
                $cls.AuxiliaryClasses | ForEach-Object { Get-DsSchemaClass -Domain $Domain -Name $_.Name }
            }
        }

        if ($Recurse) {
            Get-DsSchemaClass -Parent $cls -Recurse -Inferior:$Inferior -IncludeAuxiliary:$IncludeAuxiliary
        }
    }
}

<#
.SYNOPSIS
Get a schema attribute from Active Directory.
.DESCRIPTION
This cmdlet gets a schema attribute from Active Directory. This can be slow.
.PARAMETER SchemaId
Specify the GUID for the schema attribute.
.PARAMETER Domain
Specify the domain or server name to query for the schema attribute. Defaults to current domain.
.PARAMETER Name
Specify the LDAP name for the schema attribute to get.
.PARAMETER Attribute
Specify to get the schema class for an attribute.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.DirectoryService.DirectoryServiceSchemaAttribute[]
.EXAMPLE
Get-DsSchemaAttribute
Get all schema attributes.
.EXAMPLE
Get-DsSchemaAttribute -Domain sales.domain.com
Get all schema attributes on the sales.domain.com domain.
.EXAMPLE
Get-DsSchemaAttribute -SchemaId "28630EBB-41D5-11D1-A9C1-0000F80367C1"
Get the user principal name attribute by GUID.
.EXAMPLE
Get-DsSchemaAttribute -Name "lDAPDisplayName"
Get the user principal name attribute by LDAP name.
#>
function Get-DsSchemaAttribute {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, ParameterSetName = "FromGuid")]
        [guid]$SchemaId,
        [parameter(Mandatory, ParameterSetName = "FromName", Position = 0)]
        [string]$Name,
        [parameter(ParameterSetName = "All")]
        [parameter(ParameterSetName = "FromName")]
        [parameter(ParameterSetName = "FromGuid")]
        [parameter(ParameterSetName = "FromAttribute")]
        [string]$Domain,
        [parameter(Mandatory, ParameterSetName = "FromAttribute", ValueFromPipeline)]
        [NtCoreLib.Win32.DirectoryService.DirectoryServiceSchemaClassAttribute]$Attribute
    )

    PROCESS {
        switch ($PSCmdlet.ParameterSetName) {
            "All" {
                [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetSchemaAttributes($Domain) | Write-Output
            }
            "FromGuid" {
                [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetSchemaAttribute($Domain, $SchemaId)
            }
            "FromName" {
                [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetSchemaAttribute($Domain, $Name)
            }
            "FromAttribute" {
                [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetSchemaAttribute($Domain, $Attribute.Name)
            }
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
NtCoreLib.Security.Authorization.Sid
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
            [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetObjectSid($Domain, $DistinguishedName)
        }
        "FromObject" {
            [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetObjectSid($Object)
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
NtCoreLib.Win32.DirectoryService.DirectoryServiceSchemaClass[]
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
        $Object = [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetObject($Domain, $DistinguishedName)
    }

    $obj_class = $Object.objectClass
    if ($obj_class -eq $null -or $obj_class.Count -eq 0) {
        return
    }

    Get-DsSchemaClass -Name $obj_class[-1] -Recurse:$Recurse
}

<#
.SYNOPSIS
Get the dsHeuristics for the domain.
.DESCRIPTION
This cmdlet gets the dsHeuristics value for the domain.
.PARAMETER Domain
Specify the domain or server name to query for the object. Defaults to current domain.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.DirectoryService.DirectoryServiceHeuristics[]
.EXAMPLE
Get-DsHeuristics
Get the dsHeuristics for the current domain.
.EXAMPLE
Get-DsHeuristics -Domain SALES
Get the dsHeuristics for the SALES domain.
#>
function Get-DsHeuristics {
    param(
        [string]$Domain
    )
    [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetDsHeuristics($Domain)
}

<#
.SYNOPSIS
Get the sDRightsEffective for an object.
.DESCRIPTION
This cmdlet gets the constructed sDRightsEffective value for an object. This represents the write access to the SD the caller has.
.PARAMETER Domain
Specify the domain or server name to query for the object. Defaults to current domain.
.PARAMETER DistinguishedName
Specify the distinguished name of the object.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.SecurityInformation
.EXAMPLE
Get-DsSDRightsEffective -DistinguishedName "DC=domain,DC=local"
Get the sDRightsEffective for an object.
.EXAMPLE
Get-DsHeuristics -Domain SALES -DistinguishedName "DC=domain,DC=local"
Get the sDRightsEffective for an object in the SALES domain.
#>
function Get-DsSDRightsEffective {
    [CmdletBinding()]
    param(
        [alias("dn")]
        [parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [string]$DistinguishedName,
        [string]$Domain
    )

    PROCESS {
        [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::GetSDRightsEffective($Domain, $DistinguishedName)
    }
}

<#
.SYNOPSIS
Search for the distinguished name of the object which represents the SID.
.DESCRIPTION
This cmdlet searches for the object distinguished name for a SID.
.PARAMETER Sid
Specify the SID to lookup.
.PARAMETER Domain
Specify the domain or server name to query for the object. Defaults to current domain's global catalog.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.DirectoryService.DirectoryServiceSecurityPrincipal
.EXAMPLE
Search-DsObjectSid -Sid (Get-NtSid)
Get the name of the object for the current SID.
#>
function Search-DsObjectSid {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [string]$Domain
    )

    PROCESS {
        [NtCoreLib.Win32.DirectoryService.DirectoryServiceUtils]::FindObjectFromSid($Domain, $Sid)
    }
}