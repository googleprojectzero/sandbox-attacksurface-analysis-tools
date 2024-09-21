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
Duplicates a token to a new token.
.DESCRIPTION
This cmdlet duplicates a token to another with specified
.PARAMETER Token
Specify the token to duplicate. If not specified will use the current process token.
.PARAMETER ImpersonationLevel
If specified will duplicate the token as an impersonation token.
.PARAMETER Primary
If specified will duplicate the token as a primary token.
.PARAMETER Access
Specify the access to the new token object.
.PARAMETER Inherit
Specify the token handle is inheritable.
.PARAMETER SecurityDescriptor
Specify the new token's security descriptor.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtToken
.EXAMPLE
Copy-NtToken -Primary
Copy the current token as a primary token.
.EXAMPLE
Copy-NtToken -ImpersonationLevel Impersonation
Copy the current token as a primary token.
.EXAMPLE
Copy-NtToken -Primary -Token $token
Copy an existing token as a primary token.
#>
function Copy-NtToken {
    [CmdletBinding(DefaultParameterSetName = "Impersonation")]
    Param(
        [NtCoreLib.NtToken]$Token,
        [parameter(Mandatory, ParameterSetName = "Impersonation", Position = 0)]
        [NtCoreLib.Security.Token.SecurityImpersonationLevel]$ImpersonationLevel,
        [parameter(Mandatory, ParameterSetName = "Primary")]
        [switch]$Primary,
        [NtCoreLib.TokenAccessRights]$Access = "MaximumAllowed",
        [switch]$Inherit,
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
    )

    switch ($PSCmdlet.ParameterSetName) {
        "Impersonation" {
            $tokentype = "Impersonation"
        }
        "Primary" {
            $tokentype = "Primary"
            $ImpersonationLevel = "Anonymous"
        }
    }

    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective
    }
    else {
        $Token = $Token.Duplicate()
    }

    $attributes = "None"
    if ($Inherit) {
        $attributes = "Inherit"
    }

    Use-NtObject($Token) {
        $Token.DuplicateToken($tokentype, $ImpersonationLevel, $Access, $attributes, $SecurityDescriptor)
    }
}

<#
.SYNOPSIS
Get a token's ID values.
.DESCRIPTION
This cmdlet will get Token's ID values such as Authentication ID and Origin ID.
.PARAMETER Authentication
Specify to get authentication Id.
.PARAMETER Origin
Specify to get origin Id.
.PARAMETER Modified
Specify to get modified Id.
.PARAMETER Token
Optional token object to use to get ID. Must be accesible for Query right.
.INPUTS
None
.OUTPUTS
NtCoreLib.Luid
.EXAMPLE
Get-NtTokenId
Get the Token ID field.
.EXAMPLE
Get-NtTokenId -Token $token
Get Token ID on an explicit token object.
.EXAMPLE
Get-NtTokenId -Authentication
Get the token's Authentication ID.
.EXAMPLE
Get-NtTokenId -Origin
Get the token's Origin ID.
#>
function Get-NtTokenId {
    [CmdletBinding(DefaultParameterSetName="FromId")]
    Param(
        [NtCoreLib.NtToken]$Token,
        [Parameter(Mandatory, ParameterSetName="FromOrigin")]
        [switch]$Origin,
        [Parameter(Mandatory, ParameterSetName="FromAuth")]
        [switch]$Authentication,
        [Parameter(Mandatory, ParameterSetName="FromModified")]
        [switch]$Modified
    )
    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective -Access Query
    }
    elseif (!$Token.IsPseudoToken) {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        if ($Origin) {
            $Token.Origin | Write-Output
        } elseif ($Authentication) {
            $Token.AuthenticationId
        } elseif ($Modified) {
            $Token.ModifiedId
        } else {
            $Token.Id
        }
    }
}

<#
.SYNOPSIS
Enables virtualization on a Access Token or Process.
.DESCRIPTION
This cmdlet enables virtualization on an Access Token or Process.
.PARAMETER Token
Specify the token to modify.
.PARAMETER Process
Specify the process to modify.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Enable-NtTokenVirtualization
Enable virtualization on the current primary token.
.EXAMPLE
Enable-NtTokenVirtualization -Token $token
Enable virtualization on a specific token.
.EXAMPLE
Enable-NtTokenVirtualization -Process $proc
Enable virtualization on a specific process.
#>
function Enable-NtTokenVirtualization {
    [CmdletBinding(DefaultParameterSetName = "FromProcess")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName="FromToken")]
        [NtCoreLib.NtToken]$Token,
        [parameter(Position = 0, ParameterSetName="FromProcess")]
        [NtCoreLib.NtProcess]$Process
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromProcess" {
            if ($null -EQ $Process) {
                $Process = Get-NtProcess -Current
            }
            $Process.VirtualizationEnabled = $true
        }
        "FromToken" {
            $Token.VirtualizationEnabled = $true
        }
    }
}

<#
.SYNOPSIS
Disables virtualization on a Access Token or Process.
.DESCRIPTION
This cmdlet disables virtualization on an Access Token or Process.
.PARAMETER Token
Specify the token to modify.
.PARAMETER Process
Specify the process to modify.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Disable-NtTokenVirtualization
Disable virtualization on the current primary token.
.EXAMPLE
Disable-NtTokenVirtualization -Token $token
Disable virtualization on a specific token.
.EXAMPLE
Disable-NtTokenVirtualization -Process $proc
Disable virtualization on a specific process.
#>
function Disable-NtTokenVirtualization {
    [CmdletBinding(DefaultParameterSetName = "FromProcess")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName="FromToken")]
        [NtCoreLib.NtToken]$Token,
        [parameter(Position = 0, ParameterSetName="FromProcess")]
        [NtCoreLib.NtProcess]$Process
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromProcess" {
            if ($null -EQ $Process) {
                $Process = Get-NtProcess -Current
            }
            $Process.VirtualizationEnabled = $false
        }
        "FromToken" {
            $Token.VirtualizationEnabled = $false
        }
    }
}

<#
.SYNOPSIS
Check if a token has a specified capability.
.DESCRIPTION
This cmdlet checks if a token has a specified capability. This is primarily for checking AppContainer tokens.
.PARAMETER Token
Specify the token to check. If you do not specify the token then the effective token is used.
.PARAMETER Name
The name of the capability to check.
.INPUTS
None
.OUTPUTS
Boolean
#>
function Test-NtTokenCapability {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position = 0)]
        [string]$Name,
        [NtCoreLib.NtToken]$Token
    )

    if ($null -eq $Token) {
        [NtCoreLib.Security.NtSecurity]::CapabilityCheck($null, $Name)
    } else {
        $Token.CapabilityCheck($Name)
    }
}

<#
.SYNOPSIS
Set the state of a token's privileges.
.DESCRIPTION
This cmdlet will set the state of a token's privileges. This is commonly used to enable debug/backup privileges to perform privileged actions.
If no token is specified then the current effective token is used.
.PARAMETER Privilege
A list of privileges to set their state.
.PARAMETER Token
Optional token object to use to set privileges. Must be accesible for AdjustPrivileges right.
.PARAMETER Attribute
Specify the actual attributes to set. Defaults to Enabled.
.PARAMETER All
Set attributes for all privileges in the token.
.PARAMETER PassThru
Passthrough the updated privilege results.
.PARAMETER Disable
Disable the specified privileges.
.INPUTS
None
.OUTPUTS
List of TokenPrivilege values indicating the new state of all privileges successfully modified.
.EXAMPLE
Set-NtTokenPrivilege SeDebugPrivilege
Enable SeDebugPrivilege on the current effective token
.EXAMPLE
Set-NtTokenPrivilege SeDebugPrivilege -Attributes Disabled
Disable SeDebugPrivilege on the current effective token
.EXAMPLE
Set-NtTokenPrivilege SeBackupPrivilege, SeRestorePrivilege -Token $token
Enable SeBackupPrivilege and SeRestorePrivilege on an explicit token object.
#>
function Set-NtTokenPrivilege {
    [CmdletBinding(DefaultParameterSetName = "FromPrivilege")]
    Param(
        [NtCoreLib.NtToken]$Token,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromPrivilege")]
        [alias("Privileges")]
        [NtCoreLib.Security.Token.TokenPrivilegeValue[]]$Privilege,
        [alias("Attributes")]
        [NtCoreLib.PrivilegeAttributes]$Attribute = "Enabled",
        [switch]$Disable,
        [Parameter(Mandatory, ParameterSetName = "FromAllAttributes")]
        [switch]$All,
        [switch]$PassThru
    )

    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective
    }
    else {
        $Token = $Token.Duplicate()
    }

    if ($Disable) {
        $Attribute = "Disabled"
    }

    if ($All) {
        $Privilege = $Token.Privileges.Value
    }

    Use-NtObject($Token) {
        $result = @()
        foreach ($priv in $Privilege) {
            if ($Token.SetPrivilege($priv, $Attribute)) {
                $result += @($Token.GetPrivilege($priv))
            }
            else {
                Write-Warning "Couldn't set privilege $priv"
            }
        }
        if ($PassThru) {
            $result | Write-Output
        }
    }
}

<#
.SYNOPSIS
Enable a token's privileges.
.DESCRIPTION
This cmdlet will enable a token's privileges. This is commonly used to enable debug/backup privileges to perform privileged actions.
If no token is specified then the current effective token is used.
.PARAMETER Privilege
A list of privileges to enable.
.PARAMETER Token
Optional token object to use to enable privileges. Must be accesible for AdjustPrivileges right.
.PARAMETER PassThru
Passthrough the updated privilege results.
.INPUTS
None
.OUTPUTS
List of TokenPrivilege values indicating the new state of all privileges successfully modified.
.EXAMPLE
Enable-NtTokenPrivilege SeDebugPrivilege
Enable SeDebugPrivilege on the current effective token
.EXAMPLE
Enable-NtTokenPrivilege SeBackupPrivilege, SeRestorePrivilege -Token $token
Enable SeBackupPrivilege and SeRestorePrivilege on an explicit token object.
#>
function Enable-NtTokenPrivilege {
    [CmdletBinding(DefaultParameterSetName = "FromPrivilege")]
    Param(
        [NtCoreLib.NtToken]$Token,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromPrivilege")]
        [alias("Privileges")]
        [NtCoreLib.Security.Token.TokenPrivilegeValue[]]$Privilege,
        [switch]$PassThru
    )

    Set-NtTokenPrivilege -Token $Token -Privilege $Privilege -PassThru:$PassThru -Attribute Enabled
}

<#
.SYNOPSIS
Disable a token's privileges.
.DESCRIPTION
This cmdlet will disable a token's privileges. If no token is specified then the current effective token is used.
.PARAMETER Privilege
A list of privileges to disable.
.PARAMETER Token
Optional token object to use to disable privileges. Must be accesible for AdjustPrivileges right.
.PARAMETER PassThru
Passthrough the updated privilege results.
.INPUTS
None
.OUTPUTS
List of TokenPrivilege values indicating the new state of all privileges successfully modified.
.EXAMPLE
Disable-NtTokenPrivilege SeDebugPrivilege
Disable SeDebugPrivilege on the current effective token
.EXAMPLE
Disable-NtTokenPrivilege SeBackupPrivilege, SeRestorePrivilege -Token $token
Disable SeBackupPrivilege and SeRestorePrivilege on an explicit token object.
#>
function Disable-NtTokenPrivilege {
    [CmdletBinding(DefaultParameterSetName = "FromPrivilege")]
    Param(
        [NtCoreLib.NtToken]$Token,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromPrivilege")]
        [alias("Privileges")]
        [NtCoreLib.Security.Token.TokenPrivilegeValue[]]$Privilege,
        [switch]$PassThru
    )

    Set-NtTokenPrivilege -Token $Token -Privilege $Privilege -PassThru:$PassThru -Attribute Disabled
}

<#
.SYNOPSIS
Get the state of a token's privileges.
.DESCRIPTION
This cmdlet will get the state of a token's privileges.
.PARAMETER Privilege
A list of privileges to get their state.
.PARAMETER Token
Optional token object to use to get privileges. Must be accesible for Query right.
.INPUTS
None
.OUTPUTS
List of TokenPrivilege values indicating the state of all privileges requested.
.EXAMPLE
Get-NtTokenPrivilege
Get all privileges on the current Effective token.
.EXAMPLE
Get-NtTokenPrivilege -Token $token
Get all privileges on an explicit  token.
.EXAMPLE
Get-NtTokenPrivilege -Privilege SeDebugPrivilege
Get state of SeDebugPrivilege on the current process token
.EXAMPLE
Get-NtTokenPrivilege -Privilege SeBackupPrivilege, SeRestorePrivilege -Token $token
Get SeBackupPrivilege and SeRestorePrivilege status on an explicit token object.
#>
function Get-NtTokenPrivilege {
    Param(
        [Parameter(Position = 0, ValueFromPipeline)]
        [NtCoreLib.NtToken]$Token,
        [alias("Privileges")]
        [NtCoreLib.Security.Token.TokenPrivilegeValue[]]$Privilege
    )
    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective -Access Query
    }
    elseif (!$Token.IsPseudoToken) {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        if ($null -ne $Privilege -and $Privilege.Count -gt 0) {
            foreach ($priv in $Privilege) {
                $val = $Token.GetPrivilege($priv)
                if ($null -ne $val) {
                    $val | Write-Output
                }
                else {
                    Write-Warning "Couldn't get privilege $priv"
                }
            }
        }
        else {
            $Token.Privileges | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get a token's groups.
.DESCRIPTION
This cmdlet will get the groups for a token.
.PARAMETER Token
Optional token object to use to get groups. Must be accesible for Query right.
.PARAMETER Restricted
Return the restricted SID list.
.PARAMETER Capabilities
Return the capability SID list.
.PARAMETER Attributes
Specify attributes to filter group list on.
.INPUTS
None
.OUTPUTS
List of UserGroup values indicating the state of all groups.
.EXAMPLE
Get-NtTokenGroup
Get all groups on the effective process token
.EXAMPLE
Get-NtTokenGroup -Token $token
Get groups on an explicit token object.
.EXAMPLE
Get-NtTokenGroup -Attributes Enabled
Get groups that are enabled.
#>
function Get-NtTokenGroup {
    [CmdletBinding(DefaultParameterSetName = "Normal")]
    Param(
        [Parameter(Position = 0, ValueFromPipeline)]
        [NtCoreLib.NtToken]$Token,
        [Parameter(Mandatory, ParameterSetName = "Restricted")]
        [switch]$Restricted,
        [Parameter(Mandatory, ParameterSetName = "Capabilities")]
        [switch]$Capabilities,
        [Parameter(Mandatory, ParameterSetName = "Device")]
        [switch]$Device,
        [NtCoreLib.GroupAttributes]$Attributes = 0
    )
    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective -Access Query
    }
    elseif (!$Token.IsPseudoToken) {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        $groups = if ($Restricted) {
            $Token.RestrictedSids
        }
        elseif ($Capabilities) {
            $Token.Capabilities
        }
        elseif ($Device) {
            $Token.DeviceGroups
        }
        else {
            $Token.Groups
        }

        if ($Attributes -ne 0) {
            $groups = $groups | Where-Object { ($_.Attributes -band $Attributes) -eq $Attributes }
        }

        $groups | Write-Output
    }
}

<#
.SYNOPSIS
Sets a token's group state.
.DESCRIPTION
This cmdlet will sets the state of groups for a token.
.PARAMETER Token
Optional token object to use to set groups. Must be accesible for AdjustGroups right.
.PARAMETER Sid
Specify the list of SIDs to set.
.PARAMETER Attributes
Specify the attributes to set on the SIDs.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-NtTokenGroup -Sid "WD" -Attributes 0
Set the Everyone SID to disabled.
.EXAMPLE
Set-NtTokenGroup -Sid "WD" -Attributes Enabled
Set the Everyone SID to enabled.
#>
function Set-NtTokenGroup {
    [CmdletBinding()]
    Param(
        [NtCoreLib.NtToken]$Token,
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Security.Authorization.Sid[]]$Sid,
        [Parameter(Mandatory, Position = 1)]
        [NtCoreLib.GroupAttributes]$Attributes
    )
    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective -Access AdjustGroups
    }
    else {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        $Token.SetGroups($Sid, $Attributes)
    }
}

<#
.SYNOPSIS
Resets a token's group state.
.DESCRIPTION
This cmdlet will resets the state of groups for a token.
.PARAMETER Token
Optional token object to use to reset groups. Must be accesible for AdjustGroups right.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Reset-NtTokenGroup
Reset the groups for the current token.
.EXAMPLE
Reset-NtTokenGroup -Token $token
Reset the groups for the a specified token.
#>
function Reset-NtTokenGroup {
    [CmdletBinding()]
    Param(
        [NtCoreLib.NtToken]$Token
    )
    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective -Access AdjustGroups
    }
    else {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        $Token.ResetGroups()
    }
}

<#
.SYNOPSIS
Enable a token's group.
.DESCRIPTION
This cmdlet will enable one or more groups on a token. They can't be marked as mandatory.
.PARAMETER Token
Optional token object to use to enable groups. Must be accesible for AdjustGroups right.
.PARAMETER Sid
Specify the list of group SIDs to enable.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Enable-NtTokenGroup -Sid "WD"
Enable the Everyone SID for the current token.
.EXAMPLE
Enable-NtTokenGroup -Sid "WD" -Token $token
Enable the Everyone SID on a specified token.
#>
function Enable-NtTokenGroup {
    [CmdletBinding()]
    Param(
        [NtCoreLib.NtToken]$Token,
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Security.Authorization.Sid[]]$Sid
    )

    Set-NtTokenGroup -Token $Token -Sid $Sid -Attributes Enabled
}

<#
.SYNOPSIS
Disable a token's group.
.DESCRIPTION
This cmdlet will disable one or more groups on a token. They can't be marked as mandatory.
.PARAMETER Token
Optional token object to use to disable groups. Must be accesible for AdjustGroups right.
.PARAMETER Sid
Specify the list of group SIDs to disable.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Disable-NtTokenGroup -Sid "WD"
Disable the Everyone SID for the current token.
.EXAMPLE
Disable-NtTokenGroup -Sid "WD" -Token $token
Disable the Everyone SID on a specified token.
#>
function Disable-NtTokenGroup {
    [CmdletBinding()]
    Param(
        [NtCoreLib.NtToken]$Token,
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Security.Authorization.Sid[]]$Sid
    )

    Set-NtTokenGroup -Token $Token -Sid $Sid -Attributes Enabled
}

<#
.SYNOPSIS
Get a token's user SID or one of the other single SID values.
.DESCRIPTION
This cmdlet will get user SID for a token. Or one of the other SIDs such as Owner.
.PARAMETER Owner
Specify to get the owner.
.PARAMETER Group
Specify to get the default group.
.PARAMETER Integrity
Specify to get the integrity level.
.PARAMETER TrustLevel
Specify to get the process trust level.
.PARAMETER LogonId
Specify to get the logon SID.
.PARAMETER Package
Specify to get the AppContainer package SID.
.PARAMETER Token
Optional token object to use to get SID. Must be accesible for Query right.
.PARAMETER AsSddl
Specify to convert the SID to SDDL.
.PARAMETER AsName
Specify to convert the SID to a name.
.INPUTS
None
.OUTPUTS
NtCoreLib.Security.Authorization.Sid
.EXAMPLE
Get-NtTokenSid
Get user SID on the current effective token
.EXAMPLE
Get-NtTokenSid -Token $token
Get user SID on an explicit token object.
.EXAMPLE
Get-NtTokenSid -Group
Get the default group SID.
.EXAMPLE
Get-NtTokenSid -Owner
Get the default owner SID.
#>
function Get-NtTokenSid {
    [CmdletBinding(DefaultParameterSetName = "User")]
    Param(
        [Parameter(Position = 0, ValueFromPipeline)]
        [NtCoreLib.NtToken]$Token,
        [Parameter(Mandatory, ParameterSetName = "Owner")]
        [switch]$Owner,
        [Parameter(Mandatory, ParameterSetName = "Group")]
        [switch]$Group,
        [Parameter(Mandatory, ParameterSetName = "TrustLevel")]
        [switch]$TrustLevel,
        [Parameter(Mandatory, ParameterSetName = "Login")]
        [switch]$LogonId,
        [Parameter(Mandatory, ParameterSetName = "Integrity")]
        [switch]$Integrity,
        [Parameter(Mandatory, ParameterSetName = "Package")]
        [switch]$Package,
        [alias("ToSddl")]
        [switch]$AsSddl,
        [alias("ToName")]
        [switch]$AsName
    )
    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective -Access Query
    }
    elseif (!$Token.IsPseudoToken) {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        $sid = switch ($PsCmdlet.ParameterSetName) {
            "User" { $Token.User.Sid }
            "Owner" { $Token.Owner }
            "Group" { $Token.PrimaryGroup }
            "TrustLevel" { $Token.TrustLevel }
            "Login" { $Token.LogonSid.Sid }
            "Integrity" { $Token.IntegrityLevelSid.Sid }
            "Package" { $Token.AppContainerSid }
        }

        if ($AsSddl) {
            $sid.ToString() | Write-Output
        }
        elseif ($AsName) {
            $sid.Name | Write-Output
        }
        else {
            $sid | Write-Output
        }
    }
}

<#
.SYNOPSIS
Set a token SID.
.DESCRIPTION
This cmdlet will set a SID on the token such as default owner or group.
.PARAMETER Owner
Specify to set the default owner.
.PARAMETER Group
Specify to set the default group.
.PARAMETER Integrity
Specify to set the integrity level.
.PARAMETER Token
Optional token object to use to set group. Must be accesible for AdjustDefault right.
.PARAMETER Sid
Specify the SID to set.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-NtTokenSid -Owner -Sid "S-1-2-3-4"
Set default owner on the current effective token
.EXAMPLE
Set-NtTokenOwner -Owner -Token $token -Sid "S-1-2-3-4"
Set default owner on an explicit token object.
.EXAMPLE
Set-NtTokenOwner -Group -Sid "S-1-2-3-4"
Set the default group.
#>
function Set-NtTokenSid {
    [CmdletBinding(DefaultParameterSetName = "Normal")]
    Param(
        [Parameter(Position = 1)]
        [NtCoreLib.NtToken]$Token,
        [Parameter(Mandatory, Position = 0)]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [Parameter(Mandatory, ParameterSetName = "Owner")]
        [switch]$Owner,
        [Parameter(Mandatory, ParameterSetName = "Group")]
        [switch]$Group,
        [Parameter(Mandatory, ParameterSetName = "Integrity")]
        [switch]$Integrity
    )
    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective -Access AdjustDefault
    }
    else {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        switch ($PsCmdlet.ParameterSetName) {
            "Owner" { $Token.Owner = $Sid }
            "Group" { $Token.PrimaryGroup = $Sid }
            "Integrity" { $Token.IntegrityLevelSid = $sid }
        } }
}

<#
.SYNOPSIS
Get a token's default owner or group.
.DESCRIPTION
This cmdlet will get the default owner or group for a token.
.PARAMETER Group
Specify to get the default group rather than default owner.
.PARAMETER Token
Optional token object to use to get group. Must be accesible for Query right.
.INPUTS
None
.OUTPUTS
UserGroup for the owner.
.EXAMPLE
Get-NtTokenOwner
Get default owner on the current effective token
.EXAMPLE
Get-NtTokenOwner -Token $token
Get default owner on an explicit token object.
.EXAMPLE
Get-NtTokenOwner -Group
Get the default group.
#>
function Get-NtTokenOwner {
    [CmdletBinding()]
    Param(
        [NtCoreLib.NtToken]$Token,
        [switch]$Group
    )
    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective -Access Query
    }
    elseif (!$Token.IsPseudoToken) {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        if ($Group) {
            $Token.PrimaryGroup | Write-Output
        }
        else {
            $Token.Owner | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get a token's mandatory policy.
.DESCRIPTION
This cmdlet will get the token's mandatory policy.
.PARAMETER Group
Specify to get the default group rather than default owner.
.PARAMETER Token
Optional token object to use to get group. Must be accesible for Query right.
.INPUTS
None
.OUTPUTS
The Token Mandatory Policy
.EXAMPLE
Get-NtTokenMandatoryPolicy
Get the mandatory policy for the current effective token.
.EXAMPLE
Get-NtTokenMandatoryPolicy -Token $token
Get default owner on an explicit token object.
#>
function Get-NtTokenMandatoryPolicy {
    [CmdletBinding()]
    Param(
        [NtCoreLib.NtToken]$Token
    )
    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective -Access Query
    }
    elseif (!$Token.IsPseudoToken) {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        $Token.MandatoryPolicy
    }
}

<#
.SYNOPSIS
Remove privileges from a token.
.DESCRIPTION
This cmdlet will remove privileges from a token. Note that this completely removes the privilege, not just disable.
.PARAMETER Privileges
A list of privileges to remove.
.PARAMETER Token
Optional token object to use to remove privileges.
.INPUTS
None
.OUTPUTS
List of TokenPrivilege values indicating the new state of all privileges successfully modified.
.EXAMPLE
Remove-NtTokenPrivilege SeDebugPrivilege
Remove SeDebugPrivilege from the current effective token
.EXAMPLE
Remove-NtTokenPrivilege SeBackupPrivilege, SeRestorePrivilege -Token $token
Remove SeBackupPrivilege and SeRestorePrivilege from an explicit token object.
#>
function Remove-NtTokenPrivilege {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [alias("Privileges")]
        [NtCoreLib.Security.Token.TokenPrivilegeValue[]]$Privilege,
        [NtCoreLib.NtToken]$Token
    )
    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective
    }
    else {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        $result = @()
        foreach ($priv in $Privilege) {
            if (!$Token.RemovePrivilege($priv)) {
                Write-Warning "Can't remove $priv from token."
            }
        }
        return $result
    }
}

<#
.SYNOPSIS
Set the integrity level of a token.
.DESCRIPTION
This cmdlet will set the integrity level of a token. If you want to raise the level you must have SeTcbPrivilege otherwise you can only lower it.
If no token is specified then the current process token is used.
.PARAMETER IntegrityLevel
Specify the integrity level.
.PARAMETER Token
Optional token object to use to set privileges. Must be accesible for AdjustDefault right.
.PARAMETER Adjustment
Increment or decrement the IL level from the base specified in -IntegrityLevel.
.PARAMETER IntegrityLevelRaw
Specify the integrity level as a raw value.
.INPUTS
None
.EXAMPLE
Set-NtTokenIntegrityLevel Low
Set the current token's integrity level to low.
.EXAMPLE
Set-NtTokenIntegrityLevel Low -Token $Token
Set a specific token's integrity level to low.
.EXAMPLE
Set-NtTokenIntegrityLevel Low -Adjustment -16
Set the current token's integrity level to low minus 16.
.EXAMPLE
Set-NtTokenIntegrityLevel -IntegrityLevelRaw 0x800
Set the current token's integrity level to 0x800.
#>
function Set-NtTokenIntegrityLevel {
    [CmdletBinding(DefaultParameterSetName = "FromIL")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromIL")]
        [NtCoreLib.TokenIntegrityLevel]$IntegrityLevel,
        [NtCoreLib.NtToken]$Token,
        [Parameter(ParameterSetName = "FromIL")]
        [Int32]$Adjustment = 0,
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromRaw")]
        [Int32]$IntegrityLevelRaw
    )
    switch ($PSCmdlet.ParameterSetName) {
        "FromIL" {
            $il_raw = $IntegrityLevel.ToInt32($null) + $Adjustment
        }
        "FromRaw" {
            $il_raw = $IntegrityLevelRaw
        }
    }

    if ($Token -eq $null) {
        $Token = Get-NtToken -Effective
    }
    else {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        $Token.SetIntegrityLevelRaw($il_raw) | Out-Null
    }
}

<#
.SYNOPSIS
Get the integrity level of a token.
.DESCRIPTION
This cmdlet will gets the integrity level of a token.
.PARAMETER Token
Optional token object to use to get integrity level. Must be accesible for Query right.
.INPUTS
None
.OUTPUTS
NtCoreLib.TokenIntegrityLevel
.EXAMPLE
Get-NtTokenIntegrityLevel
Get the current token's integrity level.
.EXAMPLE
Get-NtTokenIntegrityLevel -Token $Token
Get a specific token's integrity level.
#>
function Get-NtTokenIntegrityLevel {
    [CmdletBinding(DefaultParameterSetName = "FromIL")]
    Param(
        [Parameter(Position = 0)]
        [NtCoreLib.NtToken]$Token
    )

    if ($null -eq $Token) {
        $Token = Get-NtToken -Effective
    }
    else {
        $Token = $Token.Duplicate()
    }

    Use-NtObject($Token) {
        $Token.IntegrityLevel | Write-Output
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
NtCoreLib.NtToken
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
function Get-NtTokenFromProcess {
    [CmdletBinding(DefaultParameterSetName = "FromProcess")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromProcess", Mandatory = $true)]
        [ValidateScript( { $_ -ge 0 })]
        [int]$ProcessId,
        [Parameter(ParameterSetName = "FromThread", Mandatory = $true)]
        [ValidateScript( { $_ -ge 0 })]
        [int]$ThreadId,
        [NtCoreLib.TokenAccessRights]$Access = "MaximumAllowed"
    )

    Set-NtTokenPrivilege SeDebugPrivilege
    $t = $null

    try {
        if ($PsCmdlet.ParameterSetName -eq "FromProcess") {
            $t = Use-NtObject($p = Get-NtProcess -ProcessId $ProcessId) {
                $p.GetFirstThread("DirectImpersonation")
            }
        }
        else {
            $t = Get-NtThread -ThreadId $ThreadId -Access DirectImpersonation
        }

        $current = Get-NtThread -Current -PseudoHandle
        Use-NtObject($t, $current.ImpersonateThread($t)) {
            Get-NtToken -Impersonation -Thread $current -Access $Access
        }
    }
    catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Prints the details of a token.
.DESCRIPTION
This cmdlet opens prints basic details about it a token.
.PARAMETER Token
Specify the token to format.
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
.PARAMETER SecurityAttributes
Show token security attributes.
.PARAMETER UserClaims
Show token user claim attributes.
.PARAMETER DeviceClaims
Show token device claim attributes.
.PARAMETER TrustLevel
Show token trust level.
.PARAMETER Information
Show token information such as type, impersonation level and ID.
.PARAMETER Owner
Show token owner.
.PARAMETER PrimaryGroup
Show token primary group.
.PARAMETER DefaultDacl
Show token default DACL.
.PARAMETER FullDefaultDacl
Show the default DACL in full rather than a summary.
.PARAMETER Basic
Show basic token information, User, Group, Privilege and Integrity.
.PARAMETER MandatoryPolicy
Show mandatory integrity policy.
.OUTPUTS
System.String
.EXAMPLE
Format-NtToken -Token $token
Print the user name of the token.
.EXAMPLE
Format-NtToken -Token $token -Basic
Print basic details for the token.
.EXAMPLE
Format-NtToken -Token $token -All
Print all details for the token.
.EXAMPLE
Format-NtToken -Token $token -User -Group
Print the user and groups of the token.
.EXAMPLE
Format-NtToken -Token $token -DefaultDacl
Print the default DACL of the token.
.EXAMPLE
Format-NtToken -Token $token -FullDefaultDacl
Print the default DACL of the token in full.
#>
function Format-NtToken {
    [CmdletBinding(DefaultParameterSetName = "UserOnly")]
    Param(
        [parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [NtCoreLib.NtToken]$Token,
        [parameter(ParameterSetName = "Complex")]
        [switch]$All,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Basic,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Group,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Privilege,
        [parameter(ParameterSetName = "Complex")]
        [switch]$User,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Integrity,
        [parameter(ParameterSetName = "Complex")]
        [switch]$SecurityAttributes,
        [parameter(ParameterSetName = "Complex")]
        [switch]$UserClaims,
        [parameter(ParameterSetName = "Complex")]
        [switch]$DeviceClaims,
        [parameter(ParameterSetName = "Complex")]
        [switch]$DeviceGroup,
        [parameter(ParameterSetName = "Complex")]
        [switch]$TrustLevel,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Information,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Owner,
        [parameter(ParameterSetName = "Complex")]
        [switch]$PrimaryGroup,
        [parameter(ParameterSetName = "Complex")]
        [switch]$DefaultDacl,
        [parameter(ParameterSetName = "Complex")]
        [switch]$FullDefaultDacl,
        [parameter(ParameterSetName = "Complex")]
        [switch]$MandatoryPolicy
    )

    if ($All) {
        $Group = $true
        $User = $true
        $Privilege = $true
        $Integrity = $true
        $SecurityAttributes = $true
        $DeviceClaims = $true
        $UserClaims = $true
        $TrustLevel = $true
        $Information = $true
        $Owner = $true
        $PrimaryGroup = $true
        $DefaultDacl = $true
        $DeviceGroup = $true
        $MandatoryPolicy = $true
    }
    elseif ($Basic) {
        $Group = $true
        $User = $true
        $Privilege = $true
        $Integrity = $true
    }

    if ($PSCmdlet.ParameterSetName -eq "UserOnly") {
        $token.User.ToString()
        return
    }

    if ($User) {
        "USER INFORMATION"
        "----------------"
        Format-ObjectTable $token.User.Sid | Write-Output
    }

    if ($Owner) {
        "OWNER INFORMATION"
        "---------------- "
        Format-ObjectTable $token.Owner | Write-Output
    }

    if ($PrimaryGroup) {
        "PRIMARY GROUP INFORMATION"
        "-------------------------"
        Format-ObjectTable $token.PrimaryGroup | Write-Output
    }

    if ($Group) {
        if ($Token.GroupCount -gt 0) {
            "GROUP SID INFORMATION"
            "-----------------"
            Format-ObjectTable $token.Groups | Write-Output
        }

        if ($token.AppContainer -and $token.Capabilities.Length -gt 0) {
            "APPCONTAINER INFORMATION"
            "------------------------"
            Format-ObjectTable $token.AppContainerSid | Write-Output
            "CAPABILITY SID INFORMATION"
            "----------------------"
            Format-ObjectTable $token.Capabilities | Write-Output
        }

        if ($token.Restricted -and $token.RestrictedSids.Length -gt 0) {
            if ($token.WriteRestricted) {
                "WRITE RESTRICTED SID INFORMATION"
                "--------------------------------"
            }
            else {
                "RESTRICTED SID INFORMATION"
                "--------------------------"
            }
            Format-ObjectTable $token.RestrictedSids | Write-Output
        }
    }

    if ($Privilege -and $Token.Privileges.Length -gt 0) {
        "PRIVILEGE INFORMATION"
        "---------------------"
        Format-ObjectTable $token.Privileges | Write-Output
    }

    if ($Integrity) {
        "INTEGRITY LEVEL"
        "---------------"
        Format-ObjectTable $token.IntegrityLevel | Write-Output
    }

    if ($MandatoryPolicy) {
        "MANDATORY POLICY"
        "----------------"
        Format-ObjectTable $token.MandatoryPolicy | Write-Output
    }

    if ($TrustLevel) {
        $trust_level = $token.TrustLevel
        if ($trust_level -ne $null) {
            "TRUST LEVEL"
            "-----------"
            Format-ObjectTable $trust_level | Write-Output
        }
    }

    if ($SecurityAttributes -and $Token.SecurityAttributes.Length -gt 0) {
        "SECURITY ATTRIBUTES"
        "-------------------"
        Format-ObjectTable $token.SecurityAttributes | Write-Output
    }

    if ($UserClaims -and $Token.UserClaimAttributes.Length -gt 0) {
        "USER CLAIM ATTRIBUTES"
        "-------------------"
        Format-ObjectTable $token.UserClaimAttributes | Write-Output
    }

    if ($DeviceClaims -and $Token.DeviceClaimAttributes.Length -gt 0) {
        "DEVICE CLAIM ATTRIBUTES"
        "-------------------"
        Format-ObjectTable $token.DeviceClaimAttributes | Write-Output
    }

    if ($DeviceGroup -and $Token.DeviceGroups.Length -gt 0) {
        "DEVICE GROUP SID INFORMATION"
        "----------------------------"
        Format-ObjectTable $token.DeviceGroups | Write-Output
    }

    if (($DefaultDacl -or $FullDefaultDacl) -and ($null -ne $Token.DefaultDacl)) {
        $summary = !$FullDefaultDacl
        "DEFAULT DACL"
        Format-NtAcl -Acl $Token.DefaultDacl -Type "Directory" -Name "------------" -Summary:$summary | Write-Output
        if ($summary) {
            Write-Output ""
        }
    }

    if ($Information) {
        "TOKEN INFORMATION"
        "-----------------"
        "Type          : {0}" -f $token.TokenType
        if ($token.TokenType -eq "Impersonation") {
            "Imp Level     : {0}" -f $token.ImpersonationLevel
        }
        "ID            : {0}" -f $token.Id
        "Auth ID       : {0}" -f $token.AuthenticationId
        "Origin ID     : {0}" -f $token.Origin
        "Modified ID   : {0}" -f $token.ModifiedId
        "Session ID    : {0}" -f $token.SessionId
        "Elevated      : {0}" -f $token.Elevated
        "Elevation Type: {0}" -f $token.ElevationType
        "Flags         : {0}" -f $token.Flags
    }
}

<#
.SYNOPSIS
Prints the details of the current token.
.DESCRIPTION
This cmdlet opens the current token and prints basic details about it. This is similar to the Windows whoami
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
.PARAMETER SecurityAttributes
Show token security attributes.
.PARAMETER UserClaims
Show token user claim attributes.
.PARAMETER DeviceClaims
Show token device claim attributes.
.PARAMETER TrustLevel
Show token trust level.
.PARAMETER Information
Show token information such as type, impersonation level and ID.
.PARAMETER Owner
Show token owner.
.PARAMETER PrimaryGroup
Show token primary group.
.PARAMETER DefaultDacl
Show token default DACL.
.PARAMETER FullDefaultDacl
Show the default DACL in full rather than a summary.
.PARAMETER Basic
Show basic token information, User, Group, Privilege and Integrity.
.PARAMETER MandatoryPolicy
Show mandatory integrity policy.
.PARAMETER Thread
Specify a thread to use when capturing the effective token.
.OUTPUTS
Text data
.EXAMPLE
Show-NtTokenEffective
Show only the user name of the current token.
.EXAMPLE
Show-NtTokenEffective -All
Show all details for the current token.
.EXAMPLE
Show-NtTokenEffective -Basic
Show basic details for the current token.
.EXAMPLE
Show-NtTokenEffective -User -Group
Show the user and groups of the current token.
#>
function Show-NtTokenEffective {
    [CmdletBinding(DefaultParameterSetName = "UserOnly")]
    Param(
        [parameter(ParameterSetName = "Complex")]
        [switch]$All,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Basic,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Group,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Privilege,
        [parameter(ParameterSetName = "Complex")]
        [switch]$User,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Integrity,
        [parameter(ParameterSetName = "Complex")]
        [switch]$SecurityAttributes,
        [parameter(ParameterSetName = "Complex")]
        [switch]$UserClaims,
        [parameter(ParameterSetName = "Complex")]
        [switch]$DeviceClaims,
        [parameter(ParameterSetName = "Complex")]
        [switch]$TrustLevel,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Information,
        [parameter(ParameterSetName = "Complex")]
        [switch]$Owner,
        [parameter(ParameterSetName = "Complex")]
        [switch]$PrimaryGroup,
        [parameter(ParameterSetName = "Complex")]
        [switch]$DefaultDacl,
        [parameter(ParameterSetName = "Complex")]
        [switch]$FullDefaultDacl,
        [parameter(ParameterSetName = "Complex")]
        [switch]$MandatoryPolicy,
        [NtCoreLib.NtThread]$Thread
    )

    Use-NtObject($token = Get-NtToken -Effective -Thread $Thread) {
        if ($PsCmdlet.ParameterSetName -eq "UserOnly") {
            Format-NtToken -Token $token
        }
        else {
            $args = @{
                All                = $All
                Basic              = $Basic
                Group              = $Group
                Privilege          = $Privilege
                User               = $User
                Integrity          = $Integrity
                SecurityAttributes = $SecurityAttributes
                UserClaims         = $UserClaims
                DeviceClaims       = $DeviceClaims
                TrustLevel         = $TrustLevel
                Information        = $Information
                Owner              = $Owner
                PrimaryGroup       = $PrimaryGroup
                Token              = $token
                DefaultDacl        = $DefaultDacl
                FullDefaultDacl    = $FullDefaultDacl
                MandatoryPolicy    = $MandatoryPolicy
            }
            Format-NtToken @args
        }
    }
}

function Start-NtTokenViewer {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [NtCoreLib.NtObject]$Handle,
        [string]$Text
    )

    Use-NtObject($dup_handle = $Handle.Duplicate()) {
        $cmdline = "TokenViewer --handle={0}" -f $dup_handle.Handle.DangerousGetHandle()
        if ($Text -ne "") {
            $cmdline += " ""--text=$Text"""
        }
        [NtObjectManager.Utils.PSUtils]::StartUtilityProcess("$PSScriptRoot\TokenViewer.exe", $cmdline, $false, $dup_handle)
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
When getting the name/command line only display at most this number of tokens.
.PARAMETER All
Show dialog with all access tokens.
.PARAMETER RunAsAdmin
Specify to elevate the process to admin.
.PARAMETER ServiceName
Specify the name of a service to display the token for.
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
.EXAMPLE
Show-NtToken -All -RunAsAdmin
Show a list of all accessible tokens to choose from and run as an administrator.
.EXAMPLE
Show-NtToken -ServiceName "AppInfo"
Display the primary token for the AppInfo service.
#>
function Show-NtToken {
    [CmdletBinding(DefaultParameterSetName = "FromPid")]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromToken", ValueFromPipeline)]
        [NtCoreLib.NtToken]$Token,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromProcess", ValueFromPipeline)]
        [NtCoreLib.NtProcess]$Process,
        [Parameter(Position = 0, ParameterSetName = "FromPid")]
        [int]$ProcessId = $pid,
        [Parameter(Mandatory, ParameterSetName = "FromName")]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName = "FromCommandLine")]
        [string]$CommandLine,
        [Parameter(ParameterSetName = "FromName")]
        [Parameter(ParameterSetName = "FromCommandLine")]
        [int]$MaxTokens = 0,
        [Parameter(Mandatory, ParameterSetName = "FromServiceName")]
        [string]$ServiceName,
        [Parameter(ParameterSetName = "All")]
        [switch]$All,
        [Parameter(ParameterSetName = "All")]
        [Parameter(ParameterSetName = "FromPid")]
        [Parameter(ParameterSetName = "FromServiceName")]
        [switch]$RunAsAdmin
    )

    PROCESS {
        if (-not $(Test-Path "$PSScriptRoot\TokenViewer.exe" -PathType Leaf)) {
            Write-Error "Missing token viewer application $PSScriptRoot\TokenViewer.exe"
            return
        }

        switch ($PSCmdlet.ParameterSetName) {
            "FromProcess" {
                $text = "$($Process.Name):$($Process.ProcessId)"
                Start-NtTokenViewer $Process -Text $text
            }
            "FromName" {
                Use-NtObject($ps = Get-NtProcess -Name $Name -Access QueryLimitedInformation) {
                    $result = $ps
                    if ($MaxTokens -gt 0) {
                        $result = $ps | Select-Object -First $MaxTokens
                    }
                    $result | Show-NtToken
                }
            }
            "FromCommandLine" {
                Use-NtObject($ps = Get-NtProcess -CommandLine $CommandLine -Access QueryLimitedInformation) {
                    $result = $ps
                    if ($MaxTokens -gt 0) {
                        $result = $ps | Select-Object -First $MaxTokens
                    }
                    $result | Show-NtToken
                }
            }
            "FromPid" {
                [NtObjectManager.Utils.PSUtils]::StartAdminProcess("$PSScriptRoot\TokenViewer.exe", "--pid=$ProcessId", $false, $RunAsAdmin)
            }
            "FromServiceName" {
                [NtObjectManager.Utils.PSUtils]::StartAdminProcess("$PSScriptRoot\TokenViewer.exe", "`"--service=$ServiceName`"", $false, $RunAsAdmin)
            }
            "FromToken" {
                Start-NtTokenViewer $Token
            }
            "All" {
                [NtObjectManager.Utils.PSUtils]::StartAdminProcess("$PSScriptRoot\TokenViewer.exe", "", $false, $RunAsAdmin)
            }
        }
    }
}
