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
Connect to a SAM server.
.DESCRIPTION
This cmdlet connects to a SAM server for a specified system and access rights.
.PARAMETER ServerName
Specify the target system.
.PARAMETER Access
Specify the access rights on the server.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Sam.SamServer
.EXAMPLE
Connect-SamServer
Connect to the local SAM server with maximum access.
.EXAMPLE
Connect-SamServer -ServerName "PRIMARYDC"
Connect to the SAM server on the system PRIMARYDC with maximum access.
.EXAMPLE
Connect-SamServer -Access EnumerateDomains
Connect to the local SAM server with EnumerateDomains access.
#>
function Connect-SamServer { 
    [CmdletBinding()]
    param(
        [NtCoreLib.Win32.Security.Sam.SamServerAccessRights]$Access = "MaximumAllowed",
        [string]$ServerName
    )

    [NtCoreLib.Win32.Security.Sam.SamServer]::Connect($ServerName, $Access)
}

<#
.SYNOPSIS
Get a domain object from a SAM server.
.DESCRIPTION
This cmdlet opens a domain object from a SAM server. Defaults to returning all accessible domain objects.
.PARAMETER Server
The server the query for the domain.
.PARAMETER Access
Specify the access rights on the domain object.
.PARAMETER InfoOnly
Specify to only get domain information not objects.
.PARAMETER Name
Specify to get domain by name.
.PARAMETER DomainId
Specify to get domain by SID.
.PARAMETER Builtin
Specify to open the builtin domain.
.PARAMETER User
Specify to open the user domain.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Sam.SamDomain
.EXAMPLE
Get-SamDomain -Server $server
Get all accessible domain objects from the server.
.EXAMPLE
Get-SamDomain -Server $server -InfoOnly
Get all Information only domain from the server.
.EXAMPLE
Get-SamDomain -Server $server -Name "FLUBBER"
Get the FLUBBER domain object from the server.
#>
function Get-SamDomain { 
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Sam.SamServer]$Server,
        [Parameter(Mandatory, Position = 1, ParameterSetName="FromName")]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName="FromSid")]
        [NtCoreLib.Security.Authorization.Sid]$DomainId,
        [Parameter(Mandatory, ParameterSetName="FromUser")]
        [switch]$User,
        [Parameter(Mandatory, ParameterSetName="FromBuiltin")]
        [switch]$Builtin,
        [Parameter(ParameterSetName="All")]
        [Parameter(ParameterSetName="FromName")]
        [Parameter(ParameterSetName="FromSid")]
        [Parameter(ParameterSetName="FromUser")]
        [Parameter(ParameterSetName="FromBuiltin")]
        [NtCoreLib.Win32.Security.Sam.SamDomainAccessRights]$Access = "MaximumAllowed",
        [Parameter(Mandatory, ParameterSetName="AllInfoOnly")]
        [switch]$InfoOnly
    )

    if ($InfoOnly) {
        $Server.EnumerateDomains() | ForEach-Object { 
            [PSCustomObject]@{
                Name = $_.Name
                DomainId = $Server.LookupDomain($_.Name)
            }
        }
    } else {
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Server.OpenAccessibleDomains($Access) | Write-Output
            }
            "FromName" {
                $Server.OpenDomain($Name, $Access)
            }
            "FromSid" {
                $Server.OpenDomain($DomainId, $Access)
            }
            "FromBuiltin" {
                $Server.OpenBuiltinDomain($Access)
            }
            "FromUser" {
                $Server.OpenUserDomain($Access)
            }
        }
    }
}

<#
.SYNOPSIS
Get a user object from a SAM server.
.DESCRIPTION
This cmdlet opens a user object from a SAM server.
.PARAMETER Domain
Specify the domain to get the user from.
.PARAMETER Access
Specify the access rights on the user object.
.PARAMETER InfoOnly
Specify to only get user information not objects.
.PARAMETER Name
Specify to get user by name.
.PARAMETER Sid
Specify to get user by SID.
.PARAMETER UserId
Specify to get user by ID.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Sam.SamUser
.EXAMPLE
Get-SamUser -Domain $domain
Get all accessible user objects in the domain.
.EXAMPLE
Get-SamUser -Domain $domain -InfoOnly
Get all Information only users from the server.
.EXAMPLE
Get-SamUser -Domain $domain -Name "ALICE"
Get the ALICE user object from the server.
.EXAMPLE
Get-SamUser -Domain $domain -UserId 500
Get the user object from the server with the user ID of 500.
#>
function Get-SamUser { 
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Sam.SamDomain]$Domain,
        [Parameter(Mandatory, Position = 1, ParameterSetName="FromName")]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName="FromSid")]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [Parameter(Mandatory, ParameterSetName="FromUserId")]
        [uint32]$UserId,
        [Parameter(ParameterSetName="All")]
        [Parameter(ParameterSetName="FromName")]
        [Parameter(ParameterSetName="FromSid")]
        [Parameter(ParameterSetName="FromUserId")]
        [NtCoreLib.Win32.Security.Sam.SamUserAccessRights]$Access = "MaximumAllowed",
        [Parameter(ParameterSetName="All")]
        [Parameter(ParameterSetName="AllInfoOnly")]
        [NtCoreLib.Win32.Security.Sam.UserAccountControlFlags]$Flags = 0,
        [Parameter(Mandatory, ParameterSetName="AllInfoOnly")]
        [switch]$InfoOnly
    )

    if ($InfoOnly) {
        $Domain.EnumerateUsers() | ForEach-Object { 
            [PSCustomObject]@{
                Name = $_.Name
                Sid = Get-NtSid -Sddl ($Domain.LookupId($_.RelativeId).Sddl)
            }
        }
    } else {
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Domain.OpenAccessibleUsers($Flags, $Access) | Write-Output
            }
            "FromName" {
                $Domain.OpenUser($Name, $Access)
            }
            "FromSid" {
                $Domain.OpenUser($Sid, $Access)
            }
            "FromUserId" {
                $Domain.OpenUser($UserId, $Access)
            }
        }
    }
}

<#
.SYNOPSIS
Get a group object from a SAM server.
.DESCRIPTION
This cmdlet opens a group object from a SAM server.
.PARAMETER Domain
Specify the domain to get the group from.
.PARAMETER Access
Specify the access rights on the group object.
.PARAMETER InfoOnly
Specify to only get group information not objects.
.PARAMETER Name
Specify to get group by name.
.PARAMETER Sid
Specify to get group by SID.
.PARAMETER GroupId
Specify to get group by ID.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Sam.SamGroup
.EXAMPLE
Get-SamGroup -Domain $domain
Get all accessible group objects in the domain.
.EXAMPLE
Get-SamGroup -Domain $domain -InfoOnly
Get all Information only groups from the server.
.EXAMPLE
Get-SamGroup -Domain $domain -Name "USERS"
Get the USERS group object from the server.
.EXAMPLE
Get-SamGroup -Domain $domain -GroupId 501
Get the group object from the server with the group ID of 501.
#>
function Get-SamGroup { 
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Sam.SamDomain]$Domain,
        [Parameter(Mandatory, Position = 1, ParameterSetName="FromName")]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName="FromSid")]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [Parameter(Mandatory, ParameterSetName="FromId")]
        [uint32]$GroupId,
        [Parameter(ParameterSetName="All")]
        [Parameter(ParameterSetName="FromName")]
        [Parameter(ParameterSetName="FromSid")]
        [Parameter(ParameterSetName="FromId")]
        [NtCoreLib.Win32.Security.Sam.SamGroupAccessRights]$Access = "MaximumAllowed",
        [Parameter(Mandatory, ParameterSetName="AllInfoOnly")]
        [switch]$InfoOnly
    )

    if ($InfoOnly) {
        $Domain.EnumerateGroups() | ForEach-Object { 
            [PSCustomObject]@{
                Name = $_.Name
                Sid = Get-NtSid -Sddl ($Domain.LookupId($_.RelativeId).Sddl)
            }
        }
    } else {
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Domain.OpenAccessibleGroups($Access) | Write-Output
            }
            "FromName" {
                $Domain.OpenGroup($Name, $Access)
            }
            "FromSid" {
                $Domain.OpenGroup($Sid, $Access)
            }
            "FromId" {
                $Domain.OpenGroup($GroupId, $Access)
            }
        }
    }
}

<#
.SYNOPSIS
Get a membership of a group object from a SAM server.
.DESCRIPTION
This cmdlet queries the membership of a group object from a SAM server.
.PARAMETER Group
Specify the group object to get the members from.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Sam.SamGroupMember[]
.EXAMPLE
Get-SamGroupMember -Group $group
Get members of the group objects.
#>
function Get-SamGroupMember { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Sam.SamGroup]$Group
    )

    $Group.GetMembers() | Write-Output
}

<#
.SYNOPSIS
Get a membership of an alias object from a SAM server.
.DESCRIPTION
This cmdlet queries the membership of an alias object from a SAM server.
.PARAMETER Alias
Specify the alias object to get the members from.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.Sid[]
.EXAMPLE
Get-SamGroupMember -Alias $alias
Get members of the group objects.
#>
function Get-SamAliasMember { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Sam.SamAlias]$Alias
    )

    $Alias.GetMembers() | Write-Output
}

<#
.SYNOPSIS
Get an alias object from a SAM server.
.DESCRIPTION
This cmdlet opens an alias object from a SAM server.
.PARAMETER Domain
Specify the domain to get the alias from.
.PARAMETER Access
Specify the access rights on the alias object.
.PARAMETER InfoOnly
Specify to only get alias information not objects.
.PARAMETER Name
Specify to get alias by name.
.PARAMETER Sid
Specify to get alias by SID.
.PARAMETER GroupId
Specify to get alias by ID.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Sam.SamAlias
.EXAMPLE
Get-SamAlias -Domain $domain
Get all accessible alias objects in the domain.
.EXAMPLE
Get-SamAlias -Domain $domain -InfoOnly
Get all Information only aliases from the server.
.EXAMPLE
Get-SamAlias -Domain $domain -Name "RESOURCE"
Get the RESOURCE alias object from the server.
.EXAMPLE
Get-SamAlias -Domain $domain -AliasId 502
Get the alias object from the server with the alias ID of 502.
#>
function Get-SamAlias { 
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Sam.SamDomain]$Domain,
        [Parameter(Mandatory, Position = 1, ParameterSetName="FromName")]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName="FromSid")]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [Parameter(Mandatory, ParameterSetName="FromId")]
        [uint32]$AliasId,
        [Parameter(ParameterSetName="All")]
        [Parameter(ParameterSetName="FromName")]
        [Parameter(ParameterSetName="FromSid")]
        [Parameter(ParameterSetName="FromId")]
        [NtCoreLib.Win32.Security.Sam.SamAliasAccessRights]$Access = "MaximumAllowed",
        [Parameter(Mandatory, ParameterSetName="AllInfoOnly")]
        [switch]$InfoOnly
    )

    if ($InfoOnly) {
        $Domain.EnumerateAliases() | ForEach-Object { 
            [PSCustomObject]@{
                Name = $_.Name
                Sid = Get-NtSid -Sddl ($Domain.LookupId($_.RelativeId).Sddl)
            }
        }
    } else {
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Domain.OpenAccessibleAliases($Access) | Write-Output
            }
            "FromName" {
                $Domain.OpenAlias($Name, $Access)
            }
            "FromSid" {
                $Domain.OpenAlias($Sid, $Access)
            }
            "FromId" {
                $Domain.OpenAlias($AliasId, $Access)
            }
        }
    }
}

<#
.SYNOPSIS
Create a new SAM user.
.DESCRIPTION
This cmdlet creates a new SAM user.
.PARAMETER Domain
Specify the domain to create the user in.
.PARAMETER Access
Specify the access rights on the user object.
.PARAMETER Name
Specify to name of the user.
.PARAMETER AccountType
Specify the type of account to create.
.INPUTS
None
.OUTPUTS
NtCoreLib.Win32.Security.Sam.SamUser
.EXAMPLE
New-SamUser -Domain $domain -Name "bob"
Create the bob user in the domain.
.EXAMPLE
New-SamUser -Domain $domain -Name "FILBERT$" -AccountType Workstation
Create the FILBERT$ computer account in the domain.
#>
function New-SamUser { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Win32.Security.Sam.SamDomain]$Domain,
        [Parameter(Mandatory, Position = 1)]
        [string]$Name,
        [NtCoreLib.Win32.Security.Sam.SamAliasAccessRights]$Access = "MaximumAllowed",
        [NtCoreLib.Win32.Security.Sam.SamUserAccountType]$AccountType = "User"
    )
    $Domain.CreateUser($Name, $AccountType, $Access)
}