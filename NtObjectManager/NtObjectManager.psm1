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

Set-StrictMode -Version Latest

Import-Module "$PSScriptRoot\NtObjectManager.dll"

# We use this incase we're running on a downlevel PowerShell.
function Get-IsPSCore {
    return ($PSVersionTable.Keys -contains "PSEdition") -and ($PSVersionTable.PSEdition -ne 'Desktop')
}

if ([System.Environment]::Is64BitProcess) {
    $native_dir = "$PSScriptRoot\x64"
}
else {
    $native_dir = "$PSScriptRoot\x86"
}

if (Test-Path "$native_dir\dbghelp.dll") {
    $Script:GlobalDbgHelpPath = "$native_dir\dbghelp.dll"
}
else {
    $Script:GlobalDbgHelpPath = "dbghelp.dll"
}

$Script:GlobalSymbolPath = "srv*https://msdl.microsoft.com/download/symbols"

<#
.SYNOPSIS
Get a list of ALPC Ports that can be opened by a specified token.
.DESCRIPTION
This cmdlet checks for all ALPC ports on the system and tries to determine if one or more specified tokens can connect to them.
If no tokens are specified then the current process token is used. This function searches handles for existing ALPC Port servers as you can't directly open the server object and just connecting might show inconsistent results.
.PARAMETER ProcessId
Specify a list of process IDs to open for their tokens.
.PARAMETER ProcessName
Specify a list of process names to open for their tokens.
.PARAMETER ProcessCommandLine
Specify a list of command lines to filter on find for the process tokens.
.PARAMETER Token
Specify a list token objects.
.PARAMETER Process
Specify a list process objects to use for their tokens.
.INPUTS
None
.OUTPUTS
NtObjectManager.Cmdlets.Accessible.CommonAccessCheckResult
.NOTES
For best results run this function as an administrator with SeDebugPrivilege available.
.EXAMPLE
Get-AccessibleAlpcPort
Get all ALPC Ports connectable by the current token.
.EXAMPLE
Get-AccessibleAlpcPort -ProcessIds 1234,5678
Get all ALPC Ports connectable by the process tokens of PIDs 1234 and 5678
#>
function Get-AccessibleAlpcPort {
    Param(
        [alias("ProcessIds")]
        [Int32[]]$ProcessId,
        [alias("ProcessNames")]
        [string[]]$ProcessName,
        [alias("ProcessCommandLines")]
        [string[]]$ProcessCommandLine,
        [alias("Tokens")]
        [NtApiDotNet.NtToken[]]$Token,
        [alias("Processes")]
        [NtApiDotNet.NtProcess[]]$Process
    )
    $access = Get-NtAccessMask -AlpcPortAccess Connect -ToGenericAccess
    Get-AccessibleObject -FromHandle -ProcessId $ProcessId -ProcessName $ProcessName `
        -ProcessCommandLine $ProcessCommandLine -Token $Token -Process $Process -TypeFilter "ALPC Port" -AccessRights $access
}

<#
.SYNOPSIS
Set the state of a token's privileges.
.DESCRIPTION
This cmdlet will set the state of a token's privileges. This is commonly used to enable debug/backup privileges to perform privileged actions.
If no token is specified then the current process token is used.
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
        [NtApiDotNet.NtToken]$Token,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromPrivilege")]
        [alias("Privileges")]
        [NtApiDotNet.TokenPrivilegeValue[]]$Privilege,
        [alias("Attributes")]
        [NtApiDotNet.PrivilegeAttributes]$Attribute = "Enabled",
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
        [NtApiDotNet.NtToken]$Token,
        [alias("Privileges")]
        [NtApiDotNet.TokenPrivilegeValue[]]$Privilege
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
        [NtApiDotNet.NtToken]$Token,
        [Parameter(Mandatory, ParameterSetName = "Restricted")]
        [switch]$Restricted,
        [Parameter(Mandatory, ParameterSetName = "Capabilities")]
        [switch]$Capabilities,
        [Parameter(Mandatory, ParameterSetName = "Device")]
        [switch]$Device,
        [NtApiDotNet.GroupAttributes]$Attributes = 0
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
    [CmdletBinding(DefaultParameterSetName = "Normal")]
    Param(
        [NtApiDotNet.NtToken]$Token,
        [Parameter(Mandatory, Position = 0)]
        [NtApiDotNet.Sid[]]$Sid,
        [Parameter(Mandatory, Position = 1)]
        [NtApiDotNet.GroupAttributes]$Attributes
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
.INPUTS
None
.OUTPUTS
NtApiDotNet.Sid
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
        [NtApiDotNet.NtToken]$Token,
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
        [switch]$ToSddl,
        [switch]$ToName
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

        if ($ToSddl) {
            $sid.ToString() | Write-Output
        }
        elseif ($ToName) {
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
        [NtApiDotNet.NtToken]$Token,
        [Parameter(Mandatory, Position = 0)]
        [NtApiDotNet.Sid]$Sid,
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
        [NtApiDotNet.NtToken]$Token,
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
        [NtApiDotNet.NtToken]$Token
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
        [NtApiDotNet.TokenPrivilegeValue[]]$Privilege,
        [NtApiDotNet.NtToken]$Token
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
        [NtApiDotNet.TokenIntegrityLevel]$IntegrityLevel,
        [NtApiDotNet.NtToken]$Token,
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
NtApiDotNet.TokenIntegrityLevel
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
        [NtApiDotNet.NtToken]$Token
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
function New-NtKernelCrashDump {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
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
This cmdlet will get the mitigation policies for processes it can access. The default is to return mitigations for all accessible processes.
.PARAMETER Name
The name of the processes to get mitigations for.
.PARAMETER ProcessId
One or more process IDs to get mitigations for.
.PARAMETER PageFlags
Optional flags to control what additional pages to dump
.INPUTS
None
.EXAMPLE
Get-NtProcessMitigations
Get all accessible process mitigations.
.EXAMPLE
Get-NtProcessMitigations -Name MicrosoftEdgeCP.exe
Get process mitigations for Edge content processes.
.EXAMPLE
Get-NtProcessMitigations -ProcessId 1234, 4568
Get process mitigations for two processes by ID.
#>
function Get-NtProcessMitigations {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(ParameterSetName = "FromName", Position = 0, Mandatory)]
        [string]$Name,
        [parameter(ParameterSetName = "FromProcessId", Position = 0, Mandatory)]
        [int[]]$ProcessId,
        [parameter(ParameterSetName = "FromProcess")]
        [NtApiDotNet.NtProcess[]]$Process
    )
    Set-NtTokenPrivilege SeDebugPrivilege | Out-Null
    $ps = switch ($PSCmdlet.ParameterSetName) {
        "All" {
            Get-NtProcess -Access QueryInformation
        }
        "FromName" {
            Get-NtProcess -Name $Name
        }
        "FromProcessId" {
            foreach ($id in $ProcessId) {
                Get-NtProcess -ProcessId $id
            }
        }
        "FromProcess" {
            Copy-NtObject -Object $Process
        }
    }
    Use-NtObject($ps) {
        foreach ($p in $ps) {
            try {
                Write-Output $p.Mitigations
            }
            catch {
                Write-Error $_
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
function New-NtObjectAttributes {
    Param(
        [Parameter(Position = 0)]
        [string]$Name,
        [NtApiDotNet.NtObject]$Root,
        [NtApiDotNet.AttributeFlags]$Attributes = "None",
        [NtApiDotNet.SecurityQualityOfService]$SecurityQualityOfService,
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [string]$Sddl
    )

    $sd = $SecurityDescriptor
    if ($Sddl -ne "") {
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
function New-NtSecurityQualityOfService {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
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
function Get-NtSystemEnvironmentValue {
    Param(
        [Parameter(Position = 0)]
        [string]$Name = [System.Management.Automation.Language.NullString]::Value
    )
    Set-NtTokenPrivilege SeSystemEnvironmentPrivilege | Out-Null
    $values = [NtApiDotNet.NtSystemInfo]::QuerySystemEnvironmentValueNamesAndValues()
    if ($Name -eq [string]::Empty) {
        $values
    }
    else {
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
function Get-NtLicenseValue {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
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
.PARAMETER Token
Specify a token to start the process with.
.PARAMETER ProtectionLevel
Specify the protection level when creating a protected process.
.PARAMETER DebugObject
Specify a debug object to run the process under. You need to also specify DebugProcess or DebugOnlyThisProcess flags as well.
.PARAMETER NoTokenFallback
Specify to not fallback to using CreateProcessWithLogon if CreateProcessAsUser fails.
.PARAMETER AppContainerProfile
Specify an app container profile to use.
.PARAMETER ExtendedFlags
 Specify extended creation flags.
 .PARAMETER JobList
 Specify list of jobs to assign the process to.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Win32ProcessConfig
#>
function New-Win32ProcessConfig {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$CommandLine,
        [string]$ApplicationName,
        [NtApiDotNet.SecurityDescriptor]$ProcessSecurityDescriptor,
        [NtApiDotNet.SecurityDescriptor]$ThreadSecurityDescriptor,
        [NtApiDotNet.NtProcess]$ParentProcess,
        [NtApiDotNet.Win32.CreateProcessFlags]$CreationFlags = 0,
        [NtApiDotNet.Win32.ProcessMitigationOptions]$MitigationOptions = 0,
        [switch]$TerminateOnDispose,
        [byte[]]$Environment,
        [string]$CurrentDirectory,
        [string]$Desktop,
        [string]$Title,
        [switch]$InheritHandles,
        [switch]$InheritProcessHandle,
        [switch]$InheritThreadHandle,
        [NtApiDotNet.Win32.Win32kFilterFlags]$Win32kFilterFlags = 0,
        [int]$Win32kFilterLevel = 0,
        [NtApiDotNet.NtToken]$Token,
        [NtApiDotNet.Win32.ProtectionLevel]$ProtectionLevel = "WindowsPPL",
        [NtApiDotNet.NtDebug]$DebugObject,
        [switch]$NoTokenFallback,
        [NtApiDotNet.Win32.AppContainerProfile]$AppContainerProfile,
        [NtApiDotNet.Win32.ProcessExtendedFlags]$ExtendedFlags = 0,
        [NtApiDotNet.ChildProcessMitigationFlags]$ChildProcessMitigations = 0,
        [NtApiDotNet.NtJob[]]$JobList
    )
    $config = New-Object NtApiDotNet.Win32.Win32ProcessConfig
    $config.CommandLine = $CommandLine
    if (-not [string]::IsNullOrEmpty($ApplicationName)) {
        $config.ApplicationName = $ApplicationName
    }
    $config.ProcessSecurityDescriptor = $ProcessSecurityDescriptor
    $config.ThreadSecurityDescriptor = $ThreadSecurityDescriptor
    $config.ParentProcess = $ParentProcess
    $config.CreationFlags = $CreationFlags
    $config.TerminateOnDispose = $TerminateOnDispose
    $config.Environment = $Environment
    if (-not [string]::IsNullOrEmpty($Desktop)) {
        $config.Desktop = $Desktop
    }
    if (-not [string]::IsNullOrEmpty($CurrentDirectory)) {
        $config.CurrentDirectory = $CurrentDirectory
    }
    if (-not [string]::IsNullOrEmpty($Title)) {
        $config.Title = $Title
    }
    $config.InheritHandles = $InheritHandles
    $config.InheritProcessHandle = $InheritProcessHandle
    $config.InheritThreadHandle = $InheritThreadHandle
    $config.MitigationOptions = $MitigationOptions
    $config.Win32kFilterFlags = $Win32kFilterFlags
    $config.Win32kFilterLevel = $Win32kFilterLevel
    $config.Token = $Token
    $config.ProtectionLevel = $ProtectionLevel
    $config.DebugObject = $DebugObject
    $config.NoTokenFallback = $NoTokenFallback
    if ($AppContainerProfile -ne $null) {
        $config.AppContainerSid = $AppContainerProfile.Sid
    }
    $config.ExtendedFlags = $ExtendedFlags
    $config.ChildProcessMitigations = $ChildProcessMitigations
    if ($null -ne $JobList) {
        $config.JobList.AddRange($JobList)
    }
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
.PARAMETER ProtectionLevel
Specify the protection level when creating a protected process.
.PARAMETER DebugObject
Specify a debug object to run the process under. You need to also specify DebugProcess or DebugOnlyThisProcess flags as well.
.PARAMETER NoTokenFallback
Specify to not fallback to using CreateProcessWithLogon if CreateProcessAsUser fails.
.PARAMETER Token
Specify an explicit token to create the new process with.
.PARAMETER ExtendedFlags
 Specify extended creation flags.
.PARAMETER JobList
 Specify list of jobs to assign the process to.
.PARAMETER Config
Specify the configuration for the new process.
.PARAMETER Wait
Specify to wait for the process to exit.
.PARAMETER WaitTimeout
Specify the timeout to wait for the process to exit. Defaults to infinite.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Win32Process
#>
function New-Win32Process {
    [CmdletBinding(DefaultParameterSetName = "FromArgs")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromArgs")]
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
        [NtApiDotNet.Win32.CreateProcessFlags]$CreationFlags = 0,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtApiDotNet.Win32.ProcessMitigationOptions]$MitigationOptions = 0,
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
        [Parameter(ParameterSetName = "FromArgs")]
        [NtApiDotNet.Win32.ProtectionLevel]$ProtectionLevel = "WindowsPPL",
        [Parameter(ParameterSetName = "FromArgs")]
        [NtApiDotNet.NtDebug]$DebugObject,
        [Parameter(ParameterSetName = "FromArgs")]
        [switch]$NoTokenFallback,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtApiDotNet.Win32.AppContainerProfile]$AppContainerProfile,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtApiDotNet.Win32.ProcessExtendedFlags]$ExtendedFlags = 0,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtApiDotNet.ChildProcessMitigationFlags]$ChildProcessMitigations = 0,
        [Parameter(ParameterSetName = "FromArgs")]
        [NtApiDotNet.NtJob[]]$JobList,
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromConfig")]
        [NtApiDotNet.Win32.Win32ProcessConfig]$Config,
        [switch]$Wait,
        [NtApiDotNet.NtWaitTimeout]$WaitTimeout = [NtApiDotNet.NtWaitTimeout]::Infinite
    )

    if ($null -eq $Config) {
        $Config = New-Win32ProcessConfig $CommandLine -ApplicationName $ApplicationName `
            -ProcessSecurityDescriptor $ProcessSecurityDescriptor -ThreadSecurityDescriptor $ThreadSecurityDescriptor `
            -ParentProcess $ParentProcess -CreationFlags $CreationFlags -TerminateOnDispose:$TerminateOnDispose `
            -Environment $Environment -CurrentDirectory $CurrentDirectory -Desktop $Desktop -Title $Title `
            -InheritHandles:$InheritHandles -InheritProcessHandle:$InheritProcessHandle -InheritThreadHandle:$InheritThreadHandle `
            -MitigationOptions $MitigationOptions -Token $Token -ProtectionLevel $ProtectionLevel -NoTokenFallback:$NoTokenFallback `
            -DebugObject $DebugObject -AppContainerProfile $AppContainerProfile -ExtendedFlags $ExtendedFlags `
            -ChildProcessMitigations $ChildProcessMitigations -JobList $JobList
    }

    $p = [NtApiDotNet.Win32.Win32Process]::CreateProcess($config)
    if ($Wait) {
        $p.Process.Wait($WaitTimeout)
    }
    $p | Write-Output
}

<#
.SYNOPSIS
Get the NT path for a dos path.
.DESCRIPTION
This cmdlet gets the full NT path for a specified DOS path.
.PARAMETER FullName
The DOS path to convert to NT.
.PARAMETER Resolve
Resolve relative paths to the current PS directory.
.INPUTS
string[] List of paths to convert.
.OUTPUTS
string Converted path
.EXAMPLE
Get-NtFilePath c:\Windows
Get c:\windows as an NT file path.
.EXAMPLE
Get-ChildItem c:\windows | Get-NtFilePath
Get list of NT file paths from the pipeline.
#>
function Get-NtFilePath {
    [CmdletBinding()]
    Param(
        [alias("Path")]
        [parameter(Mandatory = $true, Position = 0, ValueFromPipeline, valueFromPipelineByPropertyName)]
        [string]$FullName,
        [switch]$Resolve
    )

    PROCESS {
        $type = [NtApiDotNet.NtFileUtils]::GetDosPathType($FullName)
        $p = $FullName
        if ($Resolve) {
            if ($type -eq "Relative" -or $type -eq "Rooted") {
                $p = Resolve-Path -LiteralPath $FullName
            }
        }
        $p = [NtObjectManager.Cmdlets.Object.GetNtFileCmdlet]::ResolveWin32Path($PSCmdlet.SessionState, $p)
        Write-Output $p
    }
}

<#
.SYNOPSIS
Get the NT path type for a dos path.
.DESCRIPTION
This cmdlet gets the NT path type for a specified DOS path.
.PARAMETER FullName
The DOS path to convert to NT.
.INPUTS
string[] List of paths to convert.
.OUTPUTS
NtApiDotNet.RtlPathType
.EXAMPLE
Get-NtFilePathType c:\Windows
Get the path type for c:\windows.
#>
function Get-NtFilePathType {
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$FullName
    )

    [NtApiDotNet.NtFileUtils]::GetDosPathType($FullName)
}

<#
.SYNOPSIS
Create a new native NT process configuration.
.DESCRIPTION
This cmdlet creates a new native process configuration which you can then pass to New-NtProcess.
.PARAMETER ImagePath
The path to image file to load.
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
.PARAMETER ProhibitedImageCharacteristics
Specify prohibited image characteristics for the new process.
.PARAMETER ChildProcessMitigations
Specify child process mitigations.
.PARAMETER AdditionalFileAccess
Specify additional file access mask.
.PARAMETER InitFlags
Specify additional initialization flags.
.PARAMETER Win32Path
Specify ImagePath is a Win32 path.
.PARAMETER CaptureAdditionalInformation
Specify to capture additional information from create call.
.PARAMETER Secure
Specify to create a secure process.
.INPUTS
None
.OUTPUTS
NtApiDotNet.NtProcessCreateConfig
#>
function New-NtProcessConfig {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$ImagePath,
        [Parameter(Position = 1)]
        [string]$CommandLine,
        [NtApiDotNet.ProcessCreateFlags]$ProcessFlags = 0,
        [NtApiDotNet.ThreadCreateFlags]$ThreadFlags = 0,
        [NtApiDotNet.PsProtectedType]$ProtectedType = 0,
        [NtApiDotNet.PsProtectedSigner]$ProtectedSigner = 0,
        [NtApiDotNet.ImageCharacteristics]$ProhibitedImageCharacteristics = 0,
        [NtApiDotNet.ChildProcessMitigationFlags]$ChildProcessMitigations = 0,
        [NtApiDotNet.FileAccessRights]$AdditionalFileAccess = 0,
        [NtApiDotNet.ProcessCreateInitFlag]$InitFlags = 0,
        [switch]$TerminateOnDispose,
        [switch]$Win32Path,
        [switch]$CaptureAdditionalInformation,
        [switch]$Secure,
        [NtApiDotNet.NtObject[]]$InheritHandle
    )

    if ($Win32Path) {
        $ImagePath = Get-NtFilePath $ImagePath -Resolve
    }

    if ("" -eq $CommandLine) {
        $CommandLine = $ImagePath
    }

    $config = New-Object NtApiDotNet.NtProcessCreateConfig
    $config.ImagePath = $ImagePath
    $config.ProcessFlags = $ProcessFlags
    $config.ThreadFlags = $ThreadFlags
    $config.CommandLine = $CommandLine
    $config.ProhibitedImageCharacteristics = $ProhibitedImageCharacteristics
    $config.ChildProcessMitigations = $ChildProcessMitigations
    $config.AdditionalFileAccess = $AdditionalFileAccess
    $config.InitFlags = $InitFlags
    $config.TerminateOnDispose = $TerminateOnDispose
    if ($ProtectedType -ne 0 -or $ProtectedSigner -ne 0) {
        $config.AddProtectionLevel($ProtectedType, $ProtectedSigner)
        $config.ProcessFlags = $ProcessFlags -bor "ProtectedProcess"
    }
    $config.CaptureAdditionalInformation = $CaptureAdditionalInformation
    $config.Secure = $Secure
    if ($null -ne $InheritHandle) {
        $config.InheritHandleList.AddRange($InheritHandle)
    }

    return $config
}

<#
.SYNOPSIS
Create a new native NT process.
.DESCRIPTION
This cmdlet creates a new native NT process.
.PARAMETER Config
The configuration for the new process from New-NtProcessConfig.
.PARAMETER ReturnOnError
Specify to always return a result even on error.
.INPUTS
None
.OUTPUTS
NtApiDotNet.NtProcessCreateResult
#>
function New-NtProcess {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [NtApiDotNet.NtProcessCreateConfig]$Config,
        [switch]$ReturnOnError
    )
    [NtApiDotNet.NtProcess]::Create($Config, !$ReturnOnError)
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
function New-NtEaBuffer {
    [CmdletBinding(DefaultParameterSetName = "FromEntries")]
    Param(
        [Parameter(ParameterSetName = "FromEntries", Position = 0)]
        [Hashtable]$Entries = @{ },
        [Parameter(ParameterSetName = "FromExisting", Position = 0)]
        [NtApiDotnet.Eabuffer]$ExistingBuffer
    )

    if ($null -eq $ExistingBuffer) {
        $ea_buffer = New-Object NtApiDotNet.EaBuffer
        foreach ($entry in $Entries.Keys) {
            $ea_buffer.AddEntry($entry, $Entries.Item($entry), 0)
        }
        return $ea_buffer
    }
    else {
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
.PARAMETER ObjectPath
Specify an object path for the new section object.
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
function New-NtSectionImage {
    [CmdletBinding(DefaultParameterSetName = "FromFile")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromFile", Mandatory = $true)]
        [NtApiDotNet.NtFile]$File,
        [Parameter(Position = 0, ParameterSetName = "FromPath", Mandatory = $true)]
        [string]$Path,
        [Parameter(ParameterSetName = "FromPath")]
        [switch]$Win32Path,
        [string]$ObjectPath
    )

    if ($null -eq $File) {
        if ($Win32Path) {
            $Path = Get-NtFilePath $Path -Resolve
        }
        Use-NtObject($new_file = Get-NtFile -Path $Path -Share Read, Delete -Access GenericExecute) {
            return [NtApiDotNet.NtSection]::CreateImageSection($ObjectPath, $new_file)
        }
    }
    else {
        return [NtApiDotNet.NtSection]::CreateImageSection($ObjectPath, $File)
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
function Get-NtTokenFromProcess {
    [CmdletBinding(DefaultParameterSetName = "FromProcess")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromProcess", Mandatory = $true)]
        [ValidateScript( { $_ -ge 0 })]
        [int]$ProcessId,
        [Parameter(ParameterSetName = "FromThread", Mandatory = $true)]
        [ValidateScript( { $_ -ge 0 })]
        [int]$ThreadId,
        [NtApiDotNet.TokenAccessRights]$Access = "MaximumAllowed"
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
Gets the executable manifest for a PE file.
.DESCRIPTION
This cmdlet extracts the manifes from a PE file and extracts basic information such as UIAccess
setting or Auto Elevation.
.PARAMETER Path
Filename to get the executable manifest from.
.INPUTS
List of filenames
.OUTPUTS
NtApiDotNet.Win32.ExecutableManifest
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
function Get-ExecutableManifest {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [string]$Path
    )
    PROCESS {
        $fullpath = Resolve-Path -LiteralPath $Path
        $manifest = [NtApiDotNet.Win32.ExecutableManifest]::GetManifests($fullpath)
        Write-Output $manifest
    }
}

function Format-ObjectTable {
    Param(
        [parameter(Mandatory, Position = 0)]
        $InputObject,
        [switch]$HideTableHeaders
    )

    $output = $InputObject | Format-Table -HideTableHeaders:$HideTableHeaders | Out-String
    $output -Split "`r`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Write-Output
    Write-Output ""
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
        [NtApiDotNet.NtToken]$Token,
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
        "Type       : {0}" -f $token.TokenType
        if ($token.TokenType -eq "Impersonation") {
            "Imp Level  : {0}" -f $token.ImpersonationLevel
        }
        "ID         : {0}" -f $token.Id
        "Auth ID    : {0}" -f $token.AuthenticationId
        "Origin ID  : {0}" -f $token.Origin
        "Modified ID: {0}" -f $token.ModifiedId
        "Session ID : {0}" -f $token.SessionId
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
        [switch]$MandatoryPolicy
    )

    Use-NtObject($token = Get-NtToken -Effective) {
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

<#
.SYNOPSIS
Shows an object's security descriptor in a UI.
.DESCRIPTION
This cmdlet displays the security descriptor for an object in the standard Windows UI. If an object is passed
and the handle grants WriteDac access then the viewer will also allows you to modify the security descriptor.
.PARAMETER Object
Specify an object to use for the security descriptor.
.PARAMETER SecurityDescriptor
Specify a security descriptor.
.PARAMETER Type
Specify the NT object type for the security descriptor.
.PARAMETER Name
Optional name to display with the security descriptor.
.PARAMETER Wait
Optionally wait for the user to close the UI.
.PARAMETER ReadOnly
Optionally force the viewer to be read-only when passing an object with WriteDac access.
.PARAMETER Container
Specify the SD is a container.
.OUTPUTS
None
.EXAMPLE
Show-NtSecurityDescriptor $obj
Show the security descriptor of an object.
.EXAMPLE
Show-NtSecurityDescriptor $obj -ReadOnly
Show the security descriptor of an object as read only.
.EXAMPLE
Show-NtSecurityDescriptor $obj.SecurityDescriptor -Type $obj.NtType
Show the security descriptor for an object via it's properties.
#>
function Show-NtSecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName = "FromObject")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromObject", Mandatory = $true)]
        [NtApiDotNet.NtObject]$Object,
        [Parameter(ParameterSetName = "FromObject")]
        [switch]$ReadOnly,
        [Parameter(Position = 0, ParameterSetName = "FromAccessCheck", Mandatory = $true)]
        [NtObjectManager.Cmdlets.Accessible.CommonAccessCheckResult]$AccessCheckResult,
        [Parameter(Position = 0, ParameterSetName = "FromSecurityDescriptor", Mandatory = $true)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, ParameterSetName = "FromSecurityDescriptor")]
        [NtApiDotNet.NtType]$Type,
        [Parameter(ParameterSetName = "FromSecurityDescriptor")]
        [string]$Name = "Object",
        [Parameter(ParameterSetName = "FromSecurityDescriptor")]
        [switch]$Container,
        [switch]$Wait
    )

    switch ($PsCmdlet.ParameterSetName) {
        "FromObject" {
            if (!$Object.IsAccessMaskGranted([NtApiDotNet.GenericAccessRights]::ReadControl)) {
                Write-Error "Object doesn't have Read Control access."
                return
            }
            # For some reason ALPC ports can't be passed to child processes. So instead pass as an SD.
            if ($Object.NtType.Name -eq "ALPC Port") {
                Show-NtSecurityDescriptor $Object.SecurityDescriptor $Object.NtType -Name $Object.Name -Wait:$Wait
                return
            }
            Use-NtObject($obj = $Object.Duplicate()) {
                $cmdline = [string]::Format("ViewSecurityDescriptor {0}", $obj.Handle.DangerousGetHandle())
                if ($ReadOnly) {
                    $cmdline += " --readonly"
                }
                $config = New-Win32ProcessConfig $cmdline -ApplicationName "$PSScriptRoot\ViewSecurityDescriptor.exe" -InheritHandles
                $config.AddInheritedHandle($obj) | Out-Null
                Use-NtObject($p = New-Win32Process -Config $config) {
                    if ($Wait) {
                        $p.Process.Wait() | Out-Null
                    }
                }
            }
        }
        "FromSecurityDescriptor" {
            if ($Type -eq $null) {
                $Type = $SecurityDescriptor.NtType
            }

            if ($null -eq $Type) {
                Write-Warning "Defaulting NT type to File. This might give incorrect results."
                $Type = Get-NtType File
            }
            if (-not $Container) {
                $Container = $SecurityDescriptor.Container
            }

            $sd = [Convert]::ToBase64String($SecurityDescriptor.ToByteArray())
            Start-Process -FilePath "$PSScriptRoot\ViewSecurityDescriptor.exe" -ArgumentList @("`"$Name`"", "-$sd", "`"$($Type.Name)`"", "$Container") -Wait:$Wait
        }
        "FromAccessCheck" {
            if ($AccessCheckResult.SecurityDescriptorBase64 -eq "") {
                return
            }

            $sd = New-NtSecurityDescriptor -Base64 $AccessCheckResult.SecurityDescriptorBase64
            Show-NtSecurityDescriptor -SecurityDescriptor $sd `
                -Type $AccessCheckResult.TypeName -Name $AccessCheckResult.Name
        }
    }
}

function Format-NtAce {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline)]
        [NtApiDotNet.Ace]$Ace,
        [Parameter(Position = 1, Mandatory = $true)]
        [NtApiDotNet.NtType]$Type,
        [switch]$MapGeneric,
        [switch]$Summary,
        [switch]$Container
    )

    PROCESS {
        $mask = $ace.Mask
        $access_name = "Access"
        $mask_str = if ($ace.Type -eq "MandatoryLabel") {
            [NtApiDotNet.NtSecurity]::AccessMaskToString($mask.ToMandatoryLabelPolicy())
            $access_name = "Policy"
        }
        else {
            $Type.AccessMaskToString($Container, $mask, $MapGeneric)
        }

        if ($Summary) {
            $cond = ""
            if ($ace.IsCompoundAce) {
                $cond += "(Server:$($ace.ServerSID.Name))"
            }
            if ($ace.IsConditionalAce) {
                $cond = "($($ace.Condition))"
            }
            if ($ace.IsResourceAttributeAce) {
                $cond = "($($ace.ResourceAttribute.ToSddl()))"
            }
            if ($ace.IsObjectAce) {
                if ($null -ne $ace.ObjectType) {
                    $cond += "(OBJ:$($ace.ObjectType))"
                }
                if ($null -ne $ace.InheritedObjectType) {
                    $cond += "(IOBJ:$($ace.InheritedObjectType))"
                }
            }

            Write-Output "$($ace.Sid.Name): ($($ace.Type))($($ace.Flags))($mask_str)$cond"
        }
        else {
            Write-Output " - Type  : $($ace.Type)"
            Write-Output " - Name  : $($ace.Sid.Name)"
            Write-Output " - SID   : $($ace.Sid)"
            if ($ace.IsCompoundAce) {
                Write-Output " - ServerName: $($ace.ServerSid.Name)"
                Write-Output " - ServerSID : $($ace.ServerSid)"
            }
            Write-Output " - Mask  : 0x$($mask.ToString("X08"))"
            Write-Output " - $($access_name): $mask_str"
            Write-Output " - Flags : $($ace.Flags)"
            if ($ace.IsConditionalAce) {
                Write-Output " - Condition: $($ace.Condition)"
            }
            if ($ace.IsResourceAttributeAce) {
                Write-Output " - Attribute: $($ace.ResourceAttribute.ToSddl())"
            }
            if ($ace.IsObjectAce) {
                if ($null -ne $ace.ObjectType) {
                    Write-Output " - ObjectType: $($ace.ObjectType)"
                }
                if ($null -ne $ace.InheritedObjectType) {
                    Write-Output " - InheritedObjectType: $($ace.InheritedObjectType)"
                }
            }
            Write-Output ""
        }
    }
}

function Format-NtAcl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [AllowEmptyCollection()]
        [NtApiDotNet.Acl]$Acl,
        [Parameter(Position = 1, Mandatory)]
        [NtApiDotNet.NtType]$Type,
        [Parameter(Position = 2, Mandatory)]
        [string]$Name,
        [switch]$MapGeneric,
        [switch]$AuditOnly,
        [switch]$Summary,
        [switch]$Container
    )

    $flags = @()
    if ($Acl.Defaulted) {
        $flags += @("Defaulted")
    }

    if ($Acl.Protected) {
        $flags += @("Protected")
    }

    if ($Acl.AutoInherited) {
        $flags += @("Auto Inherited")
    }

    if ($Acl.AutoInheritReq) {
        $flags += @("Auto Inherit Requested")
    }

    if ($flags.Count -gt 0) {
        $Name = "$Name ($([string]::Join(", ", $flags)))"
    }

    if ($Acl.NullAcl) {
        if ($Summary) {
            Write-Output "$Name - <NULL>"
        }
        else {
            Write-Output $Name
            Write-Output " - <NULL ACL>"
            Write-Output ""
        }
    }
    elseif ($Acl.Count -eq 0) {
        if ($Summary) {
            Write-Output "$Name - <EMPTY>"
        }
        else {
            Write-Output $Name
            Write-Output " - <EMPTY ACL>"
            Write-Output ""
        }
    }
    else {
        Write-Output $Name
        if ($AuditOnly) {
            $Acl | Where-Object IsAuditAce | Format-NtAce -Type $Type -MapGeneric:$MapGeneric -Summary:$Summary -Container:$Container
        }
        else {
            $Acl | Format-NtAce -Type $Type -MapGeneric:$MapGeneric -Summary:$Summary -Container:$Container
        }
    }
}

<#
.SYNOPSIS
Formats an object's security descriptor as text.
.DESCRIPTION
This cmdlet formats the security descriptor to text for display in the console or piped to a file. Note that
by default the SACL won't be disabled even if you pass in a SD object with the SACL present. In those cases
change the SecurityInformation parameter to add Sacl or use ShowAll.
.PARAMETER Object
Specify an object to use for the security descriptor.
.PARAMETER SecurityDescriptor
Specify a security descriptor.
.PARAMETER Type
Specify the NT object type for the security descriptor.
.PARAMETER Path
Specify the path to an NT object for the security descriptor.
.PARAMETER SecurityInformation
Specify what parts of the security descriptor to format.
.PARAMETER MapGeneric
Specify to map access masks back to generic access rights for the object type.
.PARAMETER ToSddl
Specify to format the security descriptor as SDDL.
.PARAMETER Container
Specify to display the access mask from Container Access Rights.
.PARAMETER Acl
Specify a ACL to format.
.PARAMETER AuditOnly
Specify the ACL is a SACL otherwise a DACL.
.PARAMETER Summary
Specify to only print a shortened format removing redundant information.
.PARAMETER ShowAll
Specify to format all security descriptor information including the SACL.
.PARAMETER HideHeader
Specify to not print the security descriptor header.
.PARAMETER DisplayPath
Specify to display a path when using SecurityDescriptor or Acl formatting.
.OUTPUTS
None
.EXAMPLE
Format-NtSecurityDescriptor -Object $obj
Format the security descriptor of an object.
.EXAMPLE
Format-NtSecurityDescriptor -SecurityDescriptor $obj.SecurityDescriptor -Type $obj.NtType
Format the security descriptor for an object via it's properties.
.EXAMPLE
Format-NtSecurityDescriptor -SecurityDescriptor $sd
Format the security descriptor using a default type.
.EXAMPLE
Format-NtSecurityDescriptor -SecurityDescriptor $sd -Type File
Format the security descriptor assuming it's a File type.
.EXAMPLE
Format-NtSecurityDescriptor -Path \BaseNamedObjects
Format the security descriptor for an object from a path.
.EXAMPLE
Format-NtSecurityDescriptor -Object $obj -ToSddl
Format the security descriptor of an object as SDDL.
.EXAMPLE
Format-NtSecurityDescriptor -Object $obj -ToSddl -SecurityInformation Dacl, Label
Format the security descriptor of an object as SDDL with only DACL and Label.
#>
function Format-NtSecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName = "FromObject")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromObject", Mandatory, ValueFromPipeline)]
        [NtApiDotNet.NtObject]$Object,
        [Parameter(Position = 0, ParameterSetName = "FromSecurityDescriptor", Mandatory, ValueFromPipeline)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 0, ParameterSetName = "FromAccessCheck", Mandatory, ValueFromPipeline)]
        [NtObjectManager.Cmdlets.Accessible.CommonAccessCheckResult]$AccessCheckResult,
        [Parameter(Position = 0, ParameterSetName = "FromAcl", Mandatory)]
        [AllowEmptyCollection()]
        [NtApiDotNet.Acl]$Acl,
        [Parameter(ParameterSetName = "FromAcl")]
        [switch]$AuditOnly,
        [Parameter(Position = 1, ParameterSetName = "FromSecurityDescriptor")]
        [Parameter(Position = 1, ParameterSetName = "FromAcl")]
        [NtApiDotNet.NtType]$Type,
        [switch]$Container,
        [Parameter(Position = 0, ParameterSetName = "FromPath", Mandatory, ValueFromPipeline)]
        [string]$Path,
        [parameter(ParameterSetName = "FromPath")]
        [NtApiDotNet.NtObject]$Root,
        [NtApiDotNet.SecurityInformation]$SecurityInformation = "AllBasic",
        [switch]$MapGeneric,
        [switch]$ToSddl,
        [switch]$Summary,
        [switch]$ShowAll,
        [switch]$HideHeader,
        [Parameter(ParameterSetName = "FromSecurityDescriptor")]
        [Parameter(ParameterSetName = "FromAcl")]
        [string]$DisplayPath = ""
    )

    PROCESS {
        try {
            $sd, $t, $n = switch ($PsCmdlet.ParameterSetName) {
                "FromObject" {
                    if (!$Object.IsAccessMaskGranted([NtApiDotNet.GenericAccessRights]::ReadControl)) {
                        Write-Error "Object doesn't have Read Control access."
                        return
                    }
                    ($Object.GetSecurityDescriptor($SecurityInformation), $Object.NtType, $Object.FullPath)
                }
                "FromPath" {
                    $access = Get-NtAccessMask -SecurityInformation $SecurityInformation -ToGenericAccess
                    Use-NtObject($obj = Get-NtObject -Path $Path -Root $Root -Access $access) {
                        ($obj.GetSecurityDescriptor($SecurityInformation), $obj.NtType, $obj.FullPath)
                    }
                }
                "FromSecurityDescriptor" {
                    $sd_type = $SecurityDescriptor.NtType
                    if ($sd_type -eq $null) {
                        $sd_type = $Type
                    }
                    ($SecurityDescriptor, $sd_type, $DisplayPath)
                }
                "FromAcl" {
                    $fake_sd = New-NtSecurityDescriptor
                    if ($AuditOnly) {
                        $fake_sd.Sacl = $Acl
                        $SecurityInformation = "Sacl"
                    }
                    else {
                        $fake_sd.Dacl = $Acl
                        $SecurityInformation = "Dacl"
                    }
                    ($fake_sd, $Type, $DisplayPath)
                }
                "FromAccessCheck" {
                    if ($AccessCheckResult.SecurityDescriptorBase64 -eq "") {
                        return
                    }
                    $check_sd = New-NtSecurityDescriptor -Base64 $AccessCheckResult.SecurityDescriptorBase64
                    $Type = Get-NtType $AccessCheckResult.TypeName
                    $Name = $AccessCheckResult.Name
                    ($check_sd, $Type, $Name)
                }
            }

            $si = $SecurityInformation
            if ($ShowAll) {
                $si = [NtApiDotNet.SecurityInformation]::All
            }

            if ($ToSddl) {
                $sd.ToSddl($si) | Write-Output
                return
            }

            if ($null -eq $t) {
                Write-Warning "No type specified, formatting might be incorrect."
                $t = New-NtType Generic
            }

            if (-not $Container) {
                $Container = $sd.Container
            }

            if (!$Summary -and !$HideHeader) {
                if ($n -ne "") {
                    Write-Output "Path: $n"
                }
                Write-Output "Type: $($t.Name)"
                Write-Output "Control: $($sd.Control)"
                if ($null -ne $sd.RmControl) {
                    Write-Output $("RmControl: 0x{0:X02}" -f $sd.RmControl)
                }
                Write-Output ""
            }

            if ($null -eq $sd.Owner -and $null -eq $sd.Group `
                    -and $null -eq $sd.Dacl -and $null -eq $sd.Sacl) {
                Write-Output "<NO SECURITY INFORMATION>"
                return
            }

            if ($null -ne $sd.Owner -and (($si -band "Owner") -ne 0)) {
                $title = if ($sd.Owner.Defaulted) {
                    "<Owner> (Defaulted)"
                }
                else {
                    "<Owner>"
                }
                if ($Summary) {
                    Write-Output "$title : $($sd.Owner.Sid.Name)"
                }
                else {
                    Write-Output $title
                    Write-Output " - Name  : $($sd.Owner.Sid.Name)"
                    Write-Output " - Sid   : $($sd.Owner.Sid)"
                    Write-Output ""
                }
            }
            if ($null -ne $sd.Group -and (($si -band "Group") -ne 0)) {
                $title = if ($sd.Group.Defaulted) {
                    "<Group> (Defaulted)"
                }
                else {
                    "<Group>"
                }
                if ($Summary) {
                    Write-Output "$title : $($sd.Group.Sid.Name)"
                }
                else {
                    Write-Output $title
                    Write-Output " - Name  : $($sd.Group.Sid.Name)"
                    Write-Output " - Sid   : $($sd.Group.Sid)"
                    Write-Output ""
                }
            }
            if ($sd.DaclPresent -and (($si -band "Dacl") -ne 0)) {
                Format-NtAcl -Acl $sd.Dacl -Type $t -Name "<DACL>" -MapGeneric:$MapGeneric -Summary:$Summary -Container:$Container
            }
            if (($sd.HasAuditAce -or $sd.SaclNull) -and (($si -band "Sacl") -ne 0)) {
                Format-NtAcl -Acl $sd.Sacl -Type $t -Name "<SACL>" -MapGeneric:$MapGeneric -AuditOnly -Summary:$Summary -Container:$Container
            }
            $label = $sd.GetMandatoryLabel()
            if ($null -ne $label -and (($si -band "Label") -ne 0)) {
                Write-Output "<Mandatory Label>"
                Format-NtAce -Ace $label -Type $t -Summary:$Summary -Container:$Container
            }
            $trust = $sd.ProcessTrustLabel
            if ($null -ne $trust -and (($si -band "ProcessTrustLabel") -ne 0)) {
                Write-Output "<Process Trust Label>"
                Format-NtAce -Ace $trust -Type $t -Summary:$Summary -Container:$Container
            }
            if (($si -band "Attribute") -ne 0) {
                $attrs = $sd.ResourceAttributes
                if ($attrs.Count -gt 0) {
                    Write-Output "<Resource Attributes>"
                    foreach ($attr in $attrs) {
                        Format-NtAce -Ace $attr -Type $t -Summary:$Summary -Container:$Container
                    }
                }
            }
            if (($si -band "AccessFilter") -ne 0) {
                $filters = $sd.AccessFilters
                if ($filters.Count -gt 0) {
                    Write-Output "<Access Filters>"
                    foreach ($filter in $filters) {
                        Format-NtAce -Ace $filter -Type $t -Summary:$Summary -Container:$Container
                    }
                }
            }
            if (($si -band "Scope") -ne 0) {
                $scope = $sd.ScopedPolicyID
                if ($null -ne $scope) {
                    Write-Output "<Scoped Policy ID>"
                    Format-NtAce -Ace $scope -Type $t -Summary:$Summary -Container:$Container
                }
            }
        }
        catch {
            Write-Error $_
        }
    }
}

<#
.SYNOPSIS
Gets an IO control code structure.
.DESCRIPTION
This cmdlet gets an IO control code structure from a code or from its constituent parts.
.PARAMETER ControlCode
Specify the control code for the structure.
.PARAMETER DeviceType
Specify the device type component.
.PARAMETER Function
Specify the function code component.
.PARAMETER Method
Specify the control method component.
.PARAMETER Access
Specify the access component.
.PARAMETER LookupName
Specify to try and lookup a known name for the IO control code. If no name found will just return an empty string.
.PARAMETER All
Specify to return all known IO control codes with names.
.OUTPUTS
NtApiDotNet.NtIoControlCode
System.String
.EXAMPLE
Get-NtIoControlCode 0x110028
Get the IO control code structure for a control code.
.EXAMPLE
Get-NtIoControlCode 0x110028 -LookupName
Get the IO control code structure for a control code and lookup its name (if known).
.EXAMPLE
Get-NtIoControlCode -DeviceType NAMED_PIPE -Function 10 -Method Buffered -Access Any
Get the IO control code structure from component parts.
.EXAMPLE
Get-NtIoControlCode -DeviceType NAMED_PIPE -Function 10 -Method Buffered -Access Any -LookupName
Get the IO control code structure from component parts and lookup its name (if known).
#>
function Get-NtIoControlCode {
    [CmdletBinding(DefaultParameterSetName = "FromCode")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromCode", Mandatory = $true)]
        [int]$ControlCode,
        [Parameter(ParameterSetName = "FromParts", Mandatory = $true)]
        [NtApiDotNet.FileDeviceType]$DeviceType,
        [Parameter(ParameterSetName = "FromParts", Mandatory = $true)]
        [int]$Function,
        [Parameter(ParameterSetName = "FromParts", Mandatory = $true)]
        [NtApiDotNet.FileControlMethod]$Method,
        [Parameter(ParameterSetName = "FromParts", Mandatory = $true)]
        [NtApiDotNet.FileControlAccess]$Access,
        [Parameter(ParameterSetName = "FromParts")]
        [Parameter(ParameterSetName = "FromCode")]
        [switch]$LookupName,
        [Parameter(ParameterSetName = "FromAll", Mandatory = $true)]
        [switch]$All
    )
    $result = switch ($PsCmdlet.ParameterSetName) {
        "FromCode" {
            [NtApiDotNet.NtIoControlCode]::new($ControlCode)
        }
        "FromParts" {
            [NtApiDotNet.NtIoControlCode]::new($DeviceType, $Function, $Method, $Access)
        }
        "FromAll" {
            [NtApiDotNet.NtWellKnownIoControlCodes]::GetKnownControlCodes()
        }
    }

    if ($LookupName) {
        return [NtApiDotNet.NtWellKnownIoControlCodes]::KnownControlCodeToName($result)
    }
    $result
}

<#
.SYNOPSIS
Export details about an object to re-import in another process.
.DESCRIPTION
This function generates a short JSON string which can be used to duplicate into another process
using the Import-NtObject function. The handle must be valid when the import function is executed.
.PARAMETER Object
Specify the object to export.
.OUTPUTS
string
.EXAMPLE
Export-NtObject $obj
Export an object to a JSON string.
#>
function Export-NtObject {
    param(
        [Parameter(Position = 0, Mandatory = $true)]
        [NtApiDotNet.NtObject]$Object
    )
    $obj = [PSCustomObject]@{ProcessId = $PID; Handle = $Object.Handle.DangerousGetHandle().ToInt32() }
    $obj | ConvertTo-Json -Compress
}

<#
.SYNOPSIS
Imports an object exported with Export-NtObject.
.DESCRIPTION
This function accepts a JSON string exported from Export-NtObject which allows an object to be
duplicated between PowerShell instances. You can also specify the PID and handle separetly.
.PARAMETER Object
Specify the object to import as a JSON string.
.PARAMETER ProcessId
Specify the process ID to import from.
.PARAMETER Handle
Specify the handle value to import from.
.OUTPUTS
NtApiDotNet.NtObject (the best available type).
.EXAMPLE
Import-NtObject '{"ProcessId":3300,"Handle":2660}'
Import an object from a JSON string.
.EXAMPLE
Import-NtObject -ProcessId 3300 -Handle 2660
Import an object from separate PID and handle values.
#>
function Import-NtObject {
    [CmdletBinding(DefaultParameterSetName = "FromObject")]
    param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromObject")]
        [string]$Object,
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromPid")]
        [int]$ProcessId,
        [Parameter(Position = 1, Mandatory, ParameterSetName = "FromPid")]
        [int]$Handle
    )
    switch ($PSCmdlet.ParameterSetName) {
        "FromObject" {
            $obj = ConvertFrom-Json $Object
            Import-NtObject -ProcessId $obj.ProcessId -Handle $obj.Handle
        }
        "FromPid" {
            Use-NtObject($generic = [NtApiDotNet.NtGeneric]::DuplicateFrom($ProcessId, $Handle)) {
                $generic.ToTypedObject()
            }
        }
    }
}

<#
.SYNOPSIS
Gets the execution alias information from a name.
.DESCRIPTION
This cmdlet looks up an execution alias and tries to parse its reparse point to extract internal information.
.PARAMETER AliasName
The alias name to lookup. Can be either a full path to the alias or a name which will be found in the WindowsApps
folder.
.EXAMPLE
Get-ExecutionAlias ubuntu.exe
Get the ubuntu.exe execution alias from local appdata.
.EXAMPLE
Get-ExecutionAlias c:\path\to\alias.exe
Get the alias.exe execution alias from an absolute path.
#>
function Get-ExecutionAlias {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$AliasName
    )

    if (Test-Path $AliasName) {
        $path = Resolve-Path $AliasName
    }
    else {
        $path = $env:LOCALAPPDATA + "\Microsoft\WindowsApps\$AliasName"
    }

    Use-NtObject($file = Get-NtFile -Path $path -Win32Path -Options OpenReparsePoint, SynchronousIoNonAlert `
            -Access GenericRead, Synchronize) {
        $file.GetReparsePoint()
    }
}

<#
.SYNOPSIS
Creates a new execution alias information or updates and existing one.
.DESCRIPTION
This cmdlet creates a new execution alias for a packaged application.
.PARAMETER PackageName
The name of the UWP package.
.PARAMETER EntryPoint
The entry point of the application
.PARAMETER Target
The target executable path
.PARAMETER AppType
The application type.
.PARAMETER Version
Version number
.EXAMPLE
Set-ExecutionAlias c:\path\to\alias.exe -PackageName test -EntryPoint test!test -Target c:\test.exe -Flags 48 -Version 3
Set the alias.exe execution alias.
#>
function Set-ExecutionAlias {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Path,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$PackageName,
        [Parameter(Mandatory = $true, Position = 2)]
        [string]$EntryPoint,
        [Parameter(Mandatory = $true, Position = 3)]
        [string]$Target,
        [NtApiDotNet.ExecutionAliasAppType]$AppType = "Desktop",
        [Int32]$Version = 3
    )

    $rp = [NtApiDotNet.ExecutionAliasReparseBuffer]::new($Version, $PackageName, $EntryPoint, $Target, $AppType)
    Use-NtObject($file = New-NtFile -Path $Path -Win32Path -Options OpenReparsePoint, SynchronousIoNonAlert `
            -Access GenericWrite, Synchronize -Disposition OpenIf) {
        $file.SetReparsePoint($rp)
    }
}

function Start-NtTokenViewer {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [NtApiDotNet.NtObject]$Handle,
        [string]$Text
    )

    Use-NtObject($dup_handle = $Handle.Duplicate()) {
        $dup_handle.Inherit = $true
        $cmdline = [string]::Format("TokenViewer --handle={0}", $dup_handle.Handle.DangerousGetHandle())
        if ($Text -ne "") {
            $cmdline += " ""--text=$Text"""
        }
        $config = New-Win32ProcessConfig $cmdline -ApplicationName "$PSScriptRoot\TokenViewer.exe" -InheritHandles
        $config.InheritHandleList.Add($dup_handle.Handle.DangerousGetHandle())
        Use-NtObject(New-Win32Process -Config $config) { }
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
When showing all tokens elevate the process to admin.
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
#>
function Show-NtToken {
    [CmdletBinding(DefaultParameterSetName = "FromPid")]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromToken", ValueFromPipeline = $true)]
        [NtApiDotNet.NtToken]$Token,
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromProcess", ValueFromPipeline = $true)]
        [NtApiDotNet.NtProcess]$Process,
        [Parameter(Position = 0, ParameterSetName = "FromPid")]
        [int]$ProcessId = $pid,
        [Parameter(Mandatory = $true, ParameterSetName = "FromName")]
        [string]$Name,
        [Parameter(Mandatory = $true, ParameterSetName = "FromCommandLine")]
        [string]$CommandLine,
        [Parameter(ParameterSetName = "FromName")]
        [Parameter(ParameterSetName = "FromCommandLine")]
        [int]$MaxTokens = 0,
        [Parameter(ParameterSetName = "All")]
        [switch]$All,
        [Parameter(ParameterSetName = "All")]
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
                $cmdline = [string]::Format("TokenViewer --pid={0}", $ProcessId)
                $config = New-Win32ProcessConfig $cmdline -ApplicationName "$PSScriptRoot\TokenViewer.exe" -InheritHandles
                Use-NtObject(New-Win32Process -Config $config) {
                }
            }
            "FromToken" {
                Start-NtTokenViewer $Token
            }
            "All" {
                $verb = "open"
                if ($RunAsAdmin) {
                    $verb = "runas"
                }
                Start-Process "$PSScriptRoot\TokenViewer.exe" -Verb $verb
            }
        }
    }
}

<#
.SYNOPSIS
Displays a mapped section in a UI.
.DESCRIPTION
This cmdlet displays a section object inside a UI from where the data can be inspected or edited.
.PARAMETER Section
Specify a section object.
.PARAMETER Wait
Optionally wait for the user to close the UI.
.PARAMETER ReadOnly
Optionally force the viewer to be read-only when passing a section with Map Write access.
.PARAMETER Path
Path to a file to view as a section.
.PARAMETER ObjPath
Path to a object name to view as a section.
.OUTPUTS
None
.EXAMPLE
Show-NtSection $section
Show the mapped section.
.EXAMPLE
Show-NtSection $section -ReadOnly
Show the mapped section as read only.
.EXAMPLE
Show-NtSection $section -Wait
Show the mapped section and wait for the viewer to exit.
.EXAMPLE
Show-NtSection ([byte[]]@(0, 1, 2, 3))
Show an arbitrary byte array in the viewer.
.EXAMPLE
Show-NtSection path\to\file.bin
Show an arbitrary file in the viewer.
#>
function Show-NtSection {
    [CmdletBinding(DefaultParameterSetName = "FromSection")]
    Param(
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "FromSection")]
        [NtApiDotNet.NtSection]$Section,
        [Parameter(ParameterSetName = "FromSection")]
        [switch]$ReadOnly,
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "FromData")]
        [byte[]]$Data,
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "FromFile")]
        [string]$Path,
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "FromPath")]
        [string]$ObjPath,
        [switch]$Wait
    )
    switch ($PSCmdlet.ParameterSetName) {
        "FromSection" {
            if (!$Section.IsAccessGranted("MapRead")) {
                Write-Error "Section doesn't have Map Read access."
                return
            }
            Use-NtObject($obj = $Section.Duplicate()) {
                $obj.Inherit = $true
                $cmdline = [string]::Format("EditSection --handle {0}", $obj.Handle.DangerousGetHandle())
                if ($ReadOnly) {
                    $cmdline += " --readonly"
                }
                $config = New-Win32ProcessConfig $cmdline -ApplicationName "$PSScriptRoot\EditSection.exe" -InheritHandles
                $config.InheritHandleList.Add($obj.Handle.DangerousGetHandle())
                Use-NtObject($p = New-Win32Process -Config $config) {
                    if ($Wait) {
                        $p.Process.Wait() | Out-Null
                    }
                }
            }
        }
        "FromData" {
            if ($Data.Length -eq 0) {
                return
            }
            $tempfile = New-TemporaryFile
            $path = $tempfile.FullName
            [System.IO.File]::WriteAllBytes($path, $Data)
            Use-NtObject($p = New-Win32Process "EditSection --delete --file=""$path""" -ApplicationName "$PSScriptRoot\EditSection.exe") {
                if ($Wait) {
                    $p.Process.Wait() | Out-Null
                }
            }
        }
        "FromFile" {
            $Path = Resolve-Path $Path
            if ($Path -ne "") {
                Use-NtObject($p = New-Win32Process "EditSection --file=""$Path""" -ApplicationName "$PSScriptRoot\EditSection.exe") {
                    if ($Wait) {
                        $p.Process.Wait() | Out-Null
                    }
                }
            }
        }
        "FromPath" {
            Use-NtObject($p = New-Win32Process "EditSection --path=""$ObjPath""" -ApplicationName "$PSScriptRoot\EditSection.exe") {
                if ($Wait) {
                    $p.Process.Wait() | Out-Null
                }
            }
        }
    }
}

<#
.SYNOPSIS
Resolve the address of a list of objects.
.DESCRIPTION
This cmdlet resolves the kernel address for a list of objects. This is an expensive operation so it's designed to be
called with a list.
.PARAMETER Objects
The list of objects to resolve.
.PARAMETER PassThru
Write the object addresses to the object. Normally no output is generated.
.OUTPUTS
Int64 - If PassThru specified.
.EXAMPLE
Resolve-NtObjectAddress $obj1, $obj2; $obj1.Address
Resolve the address of two objects.
#>
function Resolve-NtObjectAddress {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [NtApiDotNet.NtObject[]]$Objects,
        [switch]$PassThru
    )
    BEGIN {
        $objs = @()
    }
    PROCESS {
        $objs += $Objects
    }
    END {
        [NtApiDotNet.NtSystemInfo]::ResolveObjectAddress([NtApiDotNet.NtObject[]]$objs)
        if ($PassThru) {
            $objs | Select-Object -ExpandProperty Address | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get the security descriptor from an object.
.DESCRIPTION
This cmdlet gets the security descriptor from an object with specified list of security information.
.PARAMETER Object
The object to get the security descriptor from.
.PARAMETER SecurityInformation
The security information to get from the object.
.PARAMETER ToSddl
Convert the security descriptor to an SDDL string.
.PARAMETER Process
Specify process to a read a security descriptor from memory.
.PARAMETER Address
Specify the address in the process to read the security descriptor.
.PARAMETER Path
Specify an object path to get the security descriptor from.
.PARAMETER TypeName
Specify the type name of the object at Path. Needed if the module cannot automatically determine the NT type to open.
.PARAMETER Root
Specify a root object for Path.
.INPUTS
NtApiDotNet.NtObject[]
.OUTPUTS
NtApiDotNet.SecurityDescriptor
string
.EXAMPLE
Get-NtSecurityDescriptor $obj
Get the security descriptor with default security information.
.EXAMPLE
Get-NtSecurityDescriptor $obj Dacl,Owner,Group
Get the security descriptor with DACL, OWNER and GROUP values.
.EXAMPLE
Get-NtSecurityDescriptor $obj Dacl -ToSddl
Get the security descriptor with DACL and output as an SDDL string.
.EXAMPLE
Get-NtSecurityDescriptor \BaseNamedObjects\ABC
Get the security descriptor from path \BaseNamedObjects\ABC.
.EXAMPLE
Get-NtSecurityDescriptor \??\C:\Windows -TypeName File
Get the security descriptor from c:\windows. Needs explicit NtType name of File to work.
.EXAMPLE
@($obj1, $obj2) | Get-NtSecurityDescriptor
Get the security descriptors from an array of objects.
.EXAMPLE
Get-NtSecurityDescriptor -Process $process -Address 0x12345678
Get the security descriptor from another process at address 0x12345678.
#>
function Get-NtSecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName = "FromObject")]
    param (
        [parameter(Mandatory, Position = 0, ValueFromPipeline, ParameterSetName = "FromObject")]
        [NtApiDotNet.NtObject]$Object,
        [parameter(Position = 1, ParameterSetName = "FromObject")]
        [parameter(Position = 1, ParameterSetName = "FromPath")]
        [parameter(ParameterSetName = "FromPid")]
        [parameter(ParameterSetName = "FromTid")]
        [NtApiDotNet.SecurityInformation]$SecurityInformation = "AllBasic",
        [parameter(Mandatory, ParameterSetName = "FromProcess")]
        [NtApiDotNet.NtProcess]$Process,
        [parameter(Mandatory, ParameterSetName = "FromProcess")]
        [int64]$Address,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromPath")]
        [string]$Path,
        [parameter(ParameterSetName = "FromPath")]
        [string]$TypeName,
        [parameter(ParameterSetName = "FromPath")]
        [NtApiDotNet.NtObject]$Root,
        [parameter(Mandatory, ParameterSetName = "FromPid")]
        [alias("pid")]
        [int]$ProcessId,
        [parameter(Mandatory, ParameterSetName = "FromTid")]
        [alias("tid")]
        [int]$ThreadId,
        [switch]$ToSddl
    )
    PROCESS {
        $sd = switch ($PsCmdlet.ParameterSetName) {
            "FromObject" {
                $Object.GetSecurityDescriptor($SecurityInformation)
            }
            "FromProcess" {
                [NtApiDotNet.SecurityDescriptor]::new($Process, [IntPtr]::new($Address))
            }
            "FromPath" {
                $mask = Get-NtAccessMask -SecurityInformation $SecurityInformation -ToGenericAccess
                Use-NtObject($obj = Get-NtObject -Path $Path -Root $Root -TypeName $TypeName -Access $mask) {
                    $obj.GetSecurityDescriptor($SecurityInformation)
                }
            }
            "FromPid" {
                $mask = Get-NtAccessMask -SecurityInformation $SecurityInformation -ToSpecificAccess Process
                Use-NtObject($obj = Get-NtProcess -ProcessId $ProcessId -Access $mask) {
                    $obj.GetSecurityDescriptor($SecurityInformation)
                }
            }
            "FromTid" {
                $mask = Get-NtAccessMask -SecurityInformation $SecurityInformation -ToSpecificAccess Thread
                Use-NtObject($obj = Get-NtThread -ThreadId $ThreadId -Access $mask) {
                    $obj.GetSecurityDescriptor($SecurityInformation)
                }
            }
        }
        if ($ToSddl) {
            $sd.ToSddl($SecurityInformation)
        }
        else {
            $sd
        }
    }
}

<#
.SYNOPSIS
Set the security descriptor for an object.
.DESCRIPTION
This cmdlet sets the security descriptor for an object with specified list of security information.
.PARAMETER Object
The object to set the security descriptor to.
.PARAMETER SecurityInformation
The security information to set obj the object.
.PARAMETER Path
Specify an object path to set the security descriptor to.
.PARAMETER Root
Specify a root object for Path.
.PARAMETER TypeName
Specify the type name of the object at Path. Needed if the module cannot automatically determine the NT type to open.
.PARAMETER SecurityDescriptor
The security descriptor to set. Can specify an SDDL string which will be auto-converted.
.INPUTS
NtApiDotNet.NtObject[]
.OUTPUTS
None
.EXAMPLE
Set-NtSecurityDescriptor $obj $sd Dacl
Set the DACL of an object using a SecurityDescriptor object.
.EXAMPLE
Set-NtSecurityDescriptor $obj "D:(A;;GA;;;WD)" Dacl
Set the DACL of an object based on an SDDL string.
#>
function Set-NtSecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName = "ToObject")]
    param (
        [parameter(Mandatory, Position = 0, ValueFromPipeline, ParameterSetName = "ToObject")]
        [NtApiDotNet.NtObject]$Object,
        [parameter(Mandatory, Position = 0, ParameterSetName = "ToPath")]
        [string]$Path,
        [parameter(ParameterSetName = "ToPath")]
        [NtApiDotNet.NtObject]$Root,
        [parameter(Mandatory, Position = 1)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [parameter(Mandatory, Position = 2)]
        [NtApiDotNet.SecurityInformation]$SecurityInformation,
        [parameter(ParameterSetName = "ToPath")]
        [string]$TypeName

    )
    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "ToObject" {
                $Object.SetSecurityDescriptor($SecurityDescriptor, $SecurityInformation)
            }
            "ToPath" {
                $access = Get-NtAccessMask -SecurityInformation $SecurityInformation -ToGenericAccess
                Use-NtObject($obj = Get-NtObject -Path $Path -Root $Root -TypeName $TypeName -Access $access) {
                    $obj.SetSecurityDescriptor($SecurityDescriptor, $SecurityInformation)
                }
            }
        }
    }
}

<#
.SYNOPSIS
Allocates a new block of virtual memory.
.DESCRIPTION
This cmdlet allocates a new block of virtual memory in a specified process with specified set of protection. Returns the address.
.PARAMETER Size
The size of the allocated memory region.
.PARAMETER BaseAddress
Optional address to allocate the memory at. Can be 0 which requests the kernel to pick an address.
.PARAMETER Process
The process to allocate the memory in, defaults to current process.
.PARAMETER AllocationType
The type of allocation to make. Defaults to Reserve and Commit.
.PARAMETER Protection
The protection for the memory region. Defaults to ReadWrite.
.OUTPUTS
int64
.EXAMPLE
$addr = Add-NtVirtualMemory 0x10000
Allocate a block 0x10000 in size.
.EXAMPLE
$addr = Add-NtVirtualMemory 0x10000 -Process $process
Allocate a block 0x10000 in size in the specified process.
.EXAMPLE
$addr = Add-NtVirtualMemory 0x10000 -AllocationType Reserve
Reserve a block 0x10000 in size but don't yet commit it.
.EXAMPLE
$addr = Add-NtVirtualMemory 0x10000 -Protection ExecuteReadWrite
Allocate a block 0x10000 in size with Read, Write and Execution protection.
#>
function Add-NtVirtualMemory {
    param (
        [parameter(Mandatory, Position = 0)]
        [int64]$Size,
        [int64]$BaseAddress,
        [NtApiDotNet.NtProcess]$Process = [NtApiDotnet.NtProcess]::Current,
        [NtApiDotNet.MemoryAllocationType]$AllocationType = "Reserve, Commit",
        [NtApiDotNet.MemoryAllocationProtect]$Protection = "ReadWrite"
    )
    $Process.AllocateMemory($BaseAddress, $Size, $AllocationType, $Protection)
}

<#
.SYNOPSIS
Deallocates a block of virtual memory.
.DESCRIPTION
This cmdlet deallocates a block of virtual memory in a specified process.
.PARAMETER Size
The size of the region to  decommit. Only valid when FreeType is Decommit.
.PARAMETER Address
The address to deallocate the memory at.
.PARAMETER Process
The process to deallocate the memory in, defaults to current process.
.PARAMETER MemoryType
The type of allocation operation to perform. Release frees the memory while
Decommit makes it inaccessible.
.OUTPUTS
None
.EXAMPLE
Remove-NtVirtualMemory $addr
Free block at $addr
.EXAMPLE
Remove-NtVirtualMemory $addr -Process $process
Free a block in the specified process.
.EXAMPLE
Remove-NtVirtualMemory $addr -Size 0x1000 -FreeType Decommit
Decommit a 4096 byte block at $addr
#>
function Remove-NtVirtualMemory {
    param (
        [parameter(Mandatory, Position = 0)]
        [int64]$Address,
        [int64]$Size,
        [NtApiDotNet.MemoryFreeType]$FreeType = "Release",
        [NtApiDotNet.NtProcess]$Process = [NtApiDotnet.NtProcess]::Current
    )
    $Process.FreeMemory($Address, $Size, $FreeType)
}

<#
.SYNOPSIS
Get information about a virtual memory region by address or for the entire process.
.DESCRIPTION
This cmdlet gets information about a virtual memory region or all regions in a process.
.PARAMETER Address
The address to get information about.
.PARAMETER Process
The process to query for memory information, defaults to current process.
.PARAMETER All
Show all memory regions.
.PARAMETER Name
Show only memory regions for the named mapped file.
.PARAMETER IncludeFree
When showing all memory regions specify to include free regions as well.
.OUTPUTS
NtApiDotNet.MemoryInformation
.EXAMPLE
Get-NtVirtualMemory $addr
Get the memory information for the specified address for the current process.
.EXAMPLE
Get-NtVirtualMemory $addr -Process $process
Get the memory information for the specified address in another process.
.EXAMPLE
Get-NtVirtualMemory
Get all memory information for the current process.
.EXAMPLE
Get-NtVirtualMemory -Process $process
Get all memory information in another process.
.EXAMPLE
Get-NtVirtualMemory -Process $process -IncludeFree
Get all memory information in another process including free regions.
.EXAMPLE
Get-NtVirtualMemory -Type Mapped
Get all mapped memory information for the current process.
.EXAMPLE
Get-NtVirtualMemory -Name file.exe
Get all mapped memory information where the mapped name is file.exe.
#>
function Get-NtVirtualMemory {
    [CmdletBinding(DefaultParameterSetName = "All")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromAddress")]
        [int64]$Address,
        [NtApiDotNet.NtProcess]$Process = [NtApiDotnet.NtProcess]::Current,
        [parameter(ParameterSetName = "All")]
        [switch]$All,
        [parameter(ParameterSetName = "All")]
        [switch]$IncludeFree,
        [NtApiDotNet.MemoryType]$Type = "All",
        [parameter(ParameterSetName = "All")]
        [NtApiDotNet.MemoryState]$State = "Commit, Reserve",
        [parameter(ParameterSetName = "All")]
        [string]$Name
    )
    switch ($PsCmdlet.ParameterSetName) {
        "FromAddress" {
            $Process.QueryMemoryInformation($Address) | Write-Output
        }
        "All" {
            if ($IncludeFree) {
                $State = $State -bor "Free"
            }
            if ($Name -ne "") {
                $Process.QueryAllMemoryInformation($Type, $State) | Where-Object MappedImageName -eq $Name | Write-Output
            }
            else {
                $Process.QueryAllMemoryInformation($Type, $State) | Write-Output
            }
        }
    }
}

<#
.SYNOPSIS
Set protection flags for a virtual memory region.
.DESCRIPTION
This cmdlet sets protection flags for a region of virtual memory in the current process or another specified process.
.PARAMETER Address
The address location to set the memory protection.
.PARAMETER Size
The size of the memory region to set.
.PARAMETER Process
The process to set the memory in, defaults to current process.
.PARAMETER Protection
Specify the new protection for the memory region.
.OUTPUTS
NtApiDotNet.MemoryAllocationProtect - The previous memory protection setting.
.EXAMPLE
Set-NtVirtualMemory $addr 0x1000 ExecuteRead
Sets the protection of a memory region to ExecuteRead.
#>
function Set-NtVirtualMemory {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position = 0)]
        [int64]$Address,
        [parameter(Mandatory, Position = 1)]
        [int64]$Size,
        [parameter(Mandatory, Position = 2)]
        [NtApiDotNet.MemoryAllocationProtect]$Protection,
        [NtApiDotNet.NtProcess]$Process = [NtApiDotnet.NtProcess]::Current
    )
    $Process.ProtectMemory($Address, $Size, $Protection)
}

<#
.SYNOPSIS
Reads bytes from a virtual memory region.
.DESCRIPTION
This cmdlet reads the bytes from a region of virtual memory in the current process or another specified process.
.PARAMETER Address
The address location to read.
.PARAMETER Size
The size of the memory to read. This is the maximum, if the memory address is invalid the returned buffer can be smaller.
.PARAMETER Process
The process to read from, defaults to current process.
.PARAMETER ReadAll
Specify to ensure you read all the requested memory from the process.
.OUTPUTS
byte[] - The array of read bytes. The size of the output might be smaller than the requested size.
.EXAMPLE
Read-NtVirtualMemory $addr 0x1000
Read up to 4096 from $addr.
.EXAMPLE
Read-NtVirtualMemory $addr 0x1000 -Process $process
Read up to 4096 from $addr in another process.
.EXAMPLE
Read-NtVirtualMemory $addr 0x1000 -ReadAll
Read up to 4096 from $addr, fail if can't read all the bytes.
#>
function Read-NtVirtualMemory {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position = 0)]
        [int64]$Address,
        [parameter(Mandatory, Position = 1)]
        [int]$Size,
        [NtApiDotNet.NtProcess]$Process = [NtApiDotnet.NtProcess]::Current,
        [switch]$ReadAll
    )
    $Process.ReadMemory($Address, $Size, $ReadAll)
}

<#
.SYNOPSIS
Writes bytes to a virtual memory region.
.DESCRIPTION
This cmdlet writes bytes to a region of virtual memory in the current process or another specified process.
.PARAMETER Address
The address location to write.
.PARAMETER Data
The data buffer to write.
.PARAMETER Process
The process to write to, defaults to current process.
.OUTPUTS
int - The length of bytes successfully written.
.EXAMPLE
Write-NtVirtualMemory $addr 0, 1, 2, 3, 4
Write 5 bytes to $addr
.EXAMPLE
Write-NtVirtualMemory $addr 0, 1, 2, 3, 4 -Process $process
Write 5 bytes to $addr in another process.
#>
function Write-NtVirtualMemory {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position = 0)]
        [int64]$Address,
        [parameter(Mandatory, Position = 1)]
        [byte[]]$Data,
        [NtApiDotNet.NtProcess]$Process = [NtApiDotnet.NtProcess]::Current
    )
    $Process.WriteMemory($Address, $Data)
}

<#
.SYNOPSIS
Get the embedded signature information from a file.
.DESCRIPTION
This cmdlet gets the embedded authenticode signature information from a file. This differs
from Get-AuthenticodeSignature in that it doesn't take into account catalog signing which is
important for tracking down PP and PPL executables.
.PARAMETER FullName
The path to the file to extract the signature from.
#>
function Get-EmbeddedAuthenticodeSignature {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$FullName
    )
    PROCESS {
        $content_type = [System.Security.Cryptography.X509Certificates.X509ContentType]::Unknown
        try {
            $path = Resolve-Path $FullName
            $content_type = [System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($Path)
        }
        catch {
            Write-Error $_
        }

        if ($content_type -ne "Authenticode") {
            return
        }

        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Path)
        $ppl = $false
        $pp = $false
        $tcb = $false
        $system = $false
        $dynamic = $false
        $elam = $false
        $store = $false
        $ium = $false

        foreach ($eku in $cert.EnhancedKeyUsageList) {
            switch ($eku.ObjectId) {
                "1.3.6.1.4.1.311.10.3.22" { $ppl = $true }
                "1.3.6.1.4.1.311.10.3.24" { $pp = $true }
                "1.3.6.1.4.1.311.10.3.23" { $tcb = $true }
                "1.3.6.1.4.1.311.10.3.6" { $system = $true }
                "1.3.6.1.4.1.311.76.11.1" { $elam = $true }
                "1.3.6.1.4.1.311.76.5.1" { $dynamic = $true }
                "1.3.6.1.4.311.76.3.1" { $store = $true }
                "1.3.6.1.4.1.311.10.3.37" { $ium = $true }
            }
        }

        $props = @{
            Path                  = $Path;
            Certificate           = $cert;
            ProtectedProcess      = $pp;
            ProtectedProcessLight = $ppl;
            Tcb                   = $tcb;
            SystemComponent       = $system;
            DynamicCodeGeneration = $dynamic;
            Elam                  = $elam;
            Store                 = $store;
            IsolatedUserMode      = $ium;
        }
        $obj = New-Object –TypeName PSObject –Prop $props
        Write-Output $obj
    }
}

<#
.SYNOPSIS
Get the name for a SID.
.DESCRIPTION
This cmdlet looks up a name for a SID and returns the name with a source for where the name came from.
.PARAMETER Sid
The SID to lookup the name for.
.PARAMETER BypassCache
Specify to bypass the name cache for this lookup.
.OUTPUTS
NtApiDotNet.SidName
.EXAMPLE
Get-NtSidName "S-1-1-0"
Lookup the name for the SID S-1-1-0.
.EXAMPLE
Get-NtSidName "S-1-1-0" -BypassCache
Lookup the name for the SID S-1-1-0 without checking the name cache.
#>
function Get-NtSidName {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [NtApiDotNet.Sid]$Sid,
        [switch]$BypassCache
    )

    PROCESS {
        [NtApiDotNet.NtSecurity]::GetNameForSid($Sid, $BypassCache)
    }
}

<#
.SYNOPSIS
Creates a symbol resolver for a process.
.DESCRIPTION
This cmdlet creates a new symbol resolver for the given process.
.PARAMETER Process
The process to create the symbol resolver on. If not specified then the current process is used.
.PARAMETER DbgHelpPath
Specify path to a dbghelp DLL to use for symbol resolving. This should be ideally the dbghelp from debugging tool for Windows
which will allow symbol servers however you can use the system version if you just want to pull symbols locally.
.PARAMETER SymbolPath
Specify path for the symbols. If not specified it will first use the _NT_SYMBOL_PATH environment variable then use the
default of 'srv*https://msdl.microsoft.com/download/symbols'
.OUTPUTS
NtApiDotNet.Win32.ISymbolResolver - The symbol resolver. Dispose after use.
.EXAMPLE
New-SymbolResolver
Get a symbol resolver for the current process with default settings.
.EXAMPLE
New-SymbolResolver -SymbolPath "c:\symbols"
Get a symbol resolver specifying for the current process specifying symbols in c:\symbols.
.EXAMPLE
New-SymbolResolver -Process $p -DbgHelpPath "c:\path\to\dbghelp.dll" -SymbolPath "srv*c:\symbols*https://blah.com/symbols"
Get a symbol resolver specifying a dbghelp path and symbol path and a specific process.
#>
function New-SymbolResolver {
    Param(
        [NtApiDotNet.NtProcess]$Process,
        [string]$DbgHelpPath,
        [string]$SymbolPath
    )
    if ($DbgHelpPath -eq "") {
        $DbgHelpPath = $Script:GlobalDbgHelpPath
    }
    if ($SymbolPath -eq "") {
        $SymbolPath = $env:_NT_SYMBOL_PATH
        if ($SymbolPath -eq "") {
            $SymbolPath = $Script:GlobalSymbolPath
        }
    }
    if ($null -eq $Process) {
        $Process = Get-NtProcess -Current
    }
    [NtApiDotNet.Win32.SymbolResolver]::Create($Process, $DbgHelpPath, $SymbolPath)
}

<#
.SYNOPSIS
Creates a NDR parser for a process.
.DESCRIPTION
This cmdlet creates a new NDR parser for the given process.
.PARAMETER Process
The process to create the NDR parser on. If not specified then the current process is used.
.PARAMETER SymbolResolver
Specify a symbol resolver for the parser. Note that this should be a resolver for the same process as we're parsing.
.PARAMETER ParserFlags
Specify flags which affect the parsing operation.
.OUTPUTS
NtApiDotNet.Ndr.NdrParser - The NDR parser.
.EXAMPLE
$ndr = New-NdrParser
Get an NDR parser for the current process.
.EXAMPLE
New-NdrParser -Process $p -SymbolResolver $resolver
Get an NDR parser for a specific process with a known resolver.
#>
function New-NdrParser {
    Param(
        [NtApiDotNet.NtProcess]$Process,
        [NtApiDotNet.Win32.ISymbolResolver]$SymbolResolver,
        [NtApiDotNet.Ndr.NdrParserFlags]$ParserFlags = 0
    )
    [NtApiDotNet.Ndr.NdrParser]::new($Process, $SymbolResolver, $ParserFlags)
}

function Convert-HashTableToIidNames {
    Param(
        [Hashtable]$IidToName,
        [NtApiDotNet.Ndr.NdrComProxyDefinition[]]$Proxy
    )
    $dict = [System.Collections.Generic.Dictionary[Guid, string]]::new()
    if ($null -ne $IidToName) {
        foreach ($pair in $IidToName.GetEnumerator()) {
            $guid = [Guid]::new($pair.Key)
            $dict.Add($guid, $pair.Value)
        }
    }

    if ($null -ne $Proxy) {
        foreach ($p in $Proxy) {
            $dict.Add($p.Iid, $p.Name)
        }
    }

    if (!$dict.ContainsKey("00000000-0000-0000-C000-000000000046")) {
        $dict.Add("00000000-0000-0000-C000-000000000046", "IUnknown")
    }

    if (!$dict.ContainsKey("00020400-0000-0000-C000-000000000046")) {
        $dict.Add("00020400-0000-0000-C000-000000000046", "IDispatch")
    }

    return $dict
}

<#
.SYNOPSIS
Parses COM proxy information from a DLL.
.DESCRIPTION
This cmdlet parses the COM proxy information from a specified DLL.
.PARAMETER Path
The path to the DLL containing the COM proxy information.
.PARAMETER Clsid
Optional CLSID for the object used to find the proxy information.
.PARAMETER Iids
Optional list of IIDs to parse from the proxy information.
.PARAMETER ParserFlags
Specify flags which affect the parsing operation.
.OUTPUTS
The parsed proxy information and complex types.
.EXAMPLE
$p = Get-NdrComProxy c:\path\to\proxy.dll
Parse the proxy information from c:\path\to\proxy.dll
.EXAMPLE
$p = Get-NdrComProxy $env:SystemRoot\system32\combase.dll -Clsid "00000320-0000-0000-C000-000000000046"
Parse the proxy information from combase.dll with a specific proxy CLSID.
.EXAMPLE
$p = Get-NdrComProxy $env:SystemRoot\system32\combase.dll -Clsid "00000320-0000-0000-C000-000000000046" -Iid "00000001-0000-0000-c000-000000000046"
Parse the proxy information from combase.dll with a specific proxy CLSID, only returning a specific IID.
#>
function Get-NdrComProxy {
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$Path,
        [Guid]$Clsid = [Guid]::Empty,
        [NtApiDotNet.Win32.ISymbolResolver]$SymbolResolver,
        [Guid[]]$Iid,
        [NtApiDotNet.Ndr.NdrParserFlags]$ParserFlags = 0
    )
    $Path = Resolve-Path $Path -ErrorAction Stop
    Use-NtObject($parser = New-NdrParser -SymbolResolver $SymbolResolver -NdrParserFlags $ParserFlags) {
        $proxies = $parser.ReadFromComProxyFile($Path, $Clsid, $Iid)
        $props = @{
            Path         = $Path;
            Proxies      = $proxies;
            ComplexTypes = $parser.ComplexTypes;
            IidToNames   = Convert-HashTableToIidNames -Proxy $proxies;
        }
        $obj = New-Object –TypeName PSObject –Prop $props
        Write-Output $obj
    }
}

<#
.SYNOPSIS
Format an NDR procedure.
.DESCRIPTION
This cmdlet formats a parsed NDR procedure.
.PARAMETER Procedure
The procedure to format.
.PARAMETER IidToName
A dictionary of IID to name mappings for parameters.
.OUTPUTS
string - The formatted procedure.
.EXAMPLE
Format-NdrProcedure $proc
Format a procedure.
.EXAMPLE
$procs = | Format-NdrProcedure
Format a list of procedures from a pipeline.
.EXAMPLE
Format-NdrProcedure $proc -IidToName @{"00000000-0000-0000-C000-000000000046"="IUnknown";}
Format a procedure with a known IID to name mapping.
#>
function Format-NdrProcedure {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline = $true)]
        [NtApiDotNet.Ndr.NdrProcedureDefinition]$Procedure,
        [Hashtable]$IidToName
    )

    BEGIN {
        $dict = Convert-HashTableToIidNames($IidToName)
        $formatter = [NtApiDotNet.Ndr.DefaultNdrFormatter]::Create($dict)
    }

    PROCESS {
        $fmt = $formatter.FormatProcedure($Procedure)
        Write-Output $fmt
    }
}

<#
.SYNOPSIS
Format an NDR complex type.
.DESCRIPTION
This cmdlet formats a parsed NDR complex type.
.PARAMETER ComplexType
The complex type to format.
.PARAMETER IidToName
A dictionary of IID to name mappings for parameters.
.OUTPUTS
string - The formatted complex type.
.EXAMPLE
Format-NdrComplexType $type
Format a complex type.
.EXAMPLE
$ndr.ComplexTypes | Format-NdrComplexType
Format a list of complex types from a pipeline.
.EXAMPLE
Format-NdrComplexType $type -IidToName @{"00000000-0000-0000-C000-000000000046"="IUnknown";}
Format a complex type with a known IID to name mapping.
#>
function Format-NdrComplexType {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtApiDotNet.Ndr.NdrComplexTypeReference[]]$ComplexType,
        [Hashtable]$IidToName
    )

    BEGIN {
        $dict = Convert-HashTableToIidNames($IidToName)
        $formatter = [NtApiDotNet.Ndr.DefaultNdrFormatter]::Create($dict)
    }

    PROCESS {
        foreach ($t in $ComplexType) {
            $formatter.FormatComplexType($t) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Format an NDR COM proxy.
.DESCRIPTION
This cmdlet formats a parsed NDR COM proxy.
.PARAMETER Proxy
The proxy to format.
.PARAMETER IidToName
A dictionary of IID to name mappings for parameters.
.PARAMETER DemangleComName
A script block which demangles a COM name (for WinRT types)
.OUTPUTS
string - The formatted proxy.
.EXAMPLE
Format-NdrComProxy $proxy
Format a COM proxy.
.EXAMPLE
$proxies = | Format-NdrComProxy
Format a list of COM proxies from a pipeline.
.EXAMPLE
Format-NdrComProxy $proxy -IidToName @{"00000000-0000-0000-C000-000000000046"="IUnknown";}
Format a COM proxy with a known IID to name mapping.
#>
function Format-NdrComProxy {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtApiDotNet.Ndr.NdrComProxyDefinition]$Proxy,
        [Hashtable]$IidToName,
        [ScriptBlock]$DemangleComName
    )

    BEGIN {
        $dict = Convert-HashTableToIidNames($IidToName)
        $formatter = if ($null -eq $DemangleComName) {
            [NtApiDotNet.Ndr.DefaultNdrFormatter]::Create($dict)
        }
        else {
            [NtApiDotNet.Ndr.DefaultNdrFormatter]::Create($dict, [Func[string, string]]$DemangleComName)
        }
    }

    PROCESS {
        $fmt = $formatter.FormatComProxy($Proxy)
        Write-Output $fmt
    }
}

<#
.SYNOPSIS
Parses RPC server information from an executable.
.DESCRIPTION
This cmdlet parses the RPC server information from a specified executable with a known offset.
.PARAMETER Path
The path to the executable containing the RPC server information.
.PARAMETER Offset
The offset into the executable where the RPC_SERVER_INTERFACE structure is loaded.
.PARAMETER ParserFlags
Specify flags which affect the parsing operation.
.OUTPUTS
The parsed RPC server information and complex types.
.EXAMPLE
$p = Get-NdrRpcServerInterface c:\path\to\server.dll 0x18000
Parse the RPC server information from c:\path\to\proxy.dll with offset 0x18000
#>
function Get-NdrRpcServerInterface {
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$Path,
        [parameter(Mandatory, Position = 1)]
        [int]$Offset,
        [NtApiDotNet.Win32.ISymbolResolver]$SymbolResolver,
        [NtApiDotNet.Ndr.NdrParserFlags]$ParserFlags = 0
    )
    $Path = Resolve-Path $Path -ErrorAction Stop
    Use-NtObject($parser = New-NdrParser -SymbolResolver $SymbolResolver -ParserFlags $ParserFlags) {
        $rpc_server = $parser.ReadFromRpcServerInterface($Path, $Offset)
        $props = @{
            Path         = $Path;
            RpcServer    = $rpc_server;
            ComplexTypes = $parser.ComplexTypes;
        }
        $obj = New-Object –TypeName PSObject –Prop $props
        Write-Output $obj
    }
}

<#
.SYNOPSIS
Format an RPC server interface type.
.DESCRIPTION
This cmdlet formats a parsed RPC server interface type.
.PARAMETER RpcServer
The RPC server interface to format.
.OUTPUTS
string - The formatted RPC server interface.
.EXAMPLE
Format-NdrRpcServerInterface $type
Format an RPC server interface type.
#>
function Format-NdrRpcServerInterface {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [NtApiDotNet.Ndr.NdrRpcServerInterface]$RpcServer
    )

    BEGIN {
        $formatter = [NtApiDotNet.Ndr.DefaultNdrFormatter]::Create()
    }

    PROCESS {
        $fmt = $formatter.FormatRpcServerInterface($RpcServer)
        Write-Output $fmt
    }
}

<#
.SYNOPSIS
Get a mapped view of a section.
.DESCRIPTION
Call Add-NtSection instead.
#>
function Get-NtMappedSection {
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtApiDotNet.NtSection]$Section,
        [parameter(Mandatory, Position = 1)]
        [NtApiDotNet.MemoryAllocationProtect]$Protection,
        [NtApiDotNet.NtProcess]$Process,
        [IntPtr]$ViewSize = 0,
        [IntPtr]$BaseAddress = 0,
        [IntPtr]$ZeroBits = 0,
        [IntPtr]$CommitSize = 0,
        [NtApiDotNet.LargeInteger]$SectionOffset,
        [NtApiDotNet.SectionInherit]$SectionInherit = [NtApiDotNet.SectionInherit]::ViewUnmap,
        [NtApiDotNet.AllocationType]$AllocationType = "None"
    )

    Write-Warning "This command has been superceded by Add-NtSection"
    if ($null -eq $Process) {
        $Process = Get-NtProcess -Current
    }

    $Section.Map($Process, $Protection, $ViewSize, $BaseAddress, `
            $ZeroBits, $CommitSize, $SectionOffset, `
            $SectionInherit, $AllocationType)
}

<#
.SYNOPSIS
Get a mapped view of a section.
.DESCRIPTION
This cmdlet calls the Map method on a section to map it into memory.
.PARAMETER Section
The section object to map.
.PARAMETER Protection
The protection of the mapping.
.PARAMETER Process
Optional process to map the section into. Default is the current process.
.PARAMETER ViewSize
The size of the view to map, 0 means map the entire section.
.PARAMETER BaseAddress
Base address for the mapping, 0 means pick a location.
.PARAMETER ZeroBits
The number of zero bits in the mapping address.
.PARAMETER CommitSize
The size of memory to commit from the section.
.PARAMETER SectionOffset
Offset into the section for the base address.
.PARAMETER SectionInherit
Inheritance flags for the section.
.PARAMETER AllocationType
The allocation type for the mapping.
.OUTPUTS
NtApiDotNet.NtMappedSection - The mapped section.
.EXAMPLE
Add-NtSection -Section $sect -Protection ReadWrite
Map the section as Read/Write.
.EXAMPLE
Add-NtSection -Section $sect -Protection ReadWrite -ViewSize 4096
Map the first 4096 bytes of the section as Read/Write.
.EXAMPLE
Add-NtSection -Section $sect -Protection ReadWrite -SectionOffset (64*1024)
Map the section starting from offset 64k.
#>
function Add-NtSection {
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtApiDotNet.NtSection]$Section,
        [parameter(Mandatory, Position = 1)]
        [NtApiDotNet.MemoryAllocationProtect]$Protection,
        [NtApiDotNet.NtProcess]$Process,
        [IntPtr]$ViewSize = 0,
        [IntPtr]$BaseAddress = 0,
        [IntPtr]$ZeroBits = 0,
        [IntPtr]$CommitSize = 0,
        [NtApiDotNet.LargeInteger]$SectionOffset,
        [NtApiDotNet.SectionInherit]$SectionInherit = [NtApiDotNet.SectionInherit]::ViewUnmap,
        [NtApiDotNet.AllocationType]$AllocationType = "None"
    )

    if ($null -eq $Process) {
        $Process = Get-NtProcess -Current
    }

    $Section.Map($Process, $Protection, $ViewSize, $BaseAddress, `
            $ZeroBits, $CommitSize, $SectionOffset, `
            $SectionInherit, $AllocationType) | Write-Output
}

<#
.SYNOPSIS
Unmap a view of a section.
.DESCRIPTION
This cmdlet unmaps a section from virtual memory.
.PARAMETER Mapping
The mapping to unmap.
.PARAMETER Address
The address to unmap.
.PARAMETER Process
Optional process to unmap from. Default is the current process.
.PARAMETER Flags
Optional flags for unmapping.
.OUTPUTS
None
.EXAMPLE
Remove-NtSection -Mapping $map
Unmap an existing section created with Add-NtSection.
.EXAMPLE
Remove-NtSection -Address $addr
Unmap an address
.EXAMPLE
Remove-NtSection -Address $addr -Process $p
Unmap an address in a specified process.
#>
function Remove-NtSection {
    [CmdletBinding(DefaultParameterSetName = "FromMapping")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromMapping")]
        [NtApiDotNet.NtMappedSection]$Mapping,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromAddress")]
        [int64]$Address,
        [parameter(Position = 1, ParameterSetName = "FromAddress")]
        [NtApiDotNet.NtProcess]$Process,
        [parameter(ParameterSetName = "FromAddress")]
        [NtApiDotNet.MemUnmapFlags]$Flags = 0
    )

    switch ($PsCmdlet.ParameterSetName) {
        "FromMapping" { $Mapping.Dispose() }
        "FromAddress" {
            if ($null -eq $Process) {
                $Process = Get-NtProcess -Current
            }

            $Process.Unmap($Address, $Flags)
        }
    }
}

<#
.SYNOPSIS
Get registered WNF subscription.
.DESCRIPTION
This cmdlet gets the registered WNF entries or a specific entry from a state name.
.PARAMETER StateName
The statename to get.
.PARAMETER DontCheckExists
Specify to not check that the WNF entry exists.
.PARAMETER Name
Lookup the state name from a well known text name.
.OUTPUTS
NtApiDotNet.NtWnf
.EXAMPLE
Get-NtWnf
Get all registered WNF entries.
.EXAMPLE
Get-NtWnf 0x12345678
Get a WNF entry from a state name.
.EXAMPLE
Get-NtWnf 0x12345678 -DontCheckExists
Get a WNF entry from a state name but don't check if it exists.
.EXAMPLE
Get-NtWnf "WNF_AOW_BOOT_PROGRESS"
Get a WNF entry from a name.
#>
function Get-NtWnf {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Position = 0, Mandatory, ParameterSetName = "StateName")]
        [uint64]$StateName,
        [parameter(ParameterSetName = "StateName")]
        [parameter(ParameterSetName = "Name")]
        [switch]$DontCheckExists,
        [parameter(Position = 0, Mandatory, ParameterSetName = "Name")]
        [string]$Name
    )
    switch ($PSCmdlet.ParameterSetName) {
        "All" {
            [NtApiDotNet.NtWnf]::GetRegisteredNotifications()
        }
        "StateName" {
            [NtApiDotNet.NtWnf]::Open($StateName, -not $DontCheckExists)
        }
        "Name" {
            [NtApiDotNet.NtWnf]::Open($Name, -not $DontCheckExists)
        }
    }
}

<#
.SYNOPSIS
Get the cached signing level for a file.
.DESCRIPTION
This cmdlet gets the cached signing level for a specified file.
.PARAMETER Path
The file to get the cached signing level from.
.PARAMETER Win32Path
Specify to treat Path as a Win32 path.
.PARAMETER FromEa
Specify whether to the read the cached signing level from the extended attribute.
.OUTPUTS
NtApiDotNet.CachedSigningLevel
.EXAMPLE
Get-NtCachedSigningLevel \??\c:\path\to\file.dll
Get the cached signing level from \??\c:\path\to\file.dll
.EXAMPLE
Get-NtCachedSigningLevel c:\path\to\file.dll -Win32Path
Get the cached signing level from c:\path\to\file.dll converting from a win32 path.
.EXAMPLE
Get-NtCachedSigningLevel \??\c:\path\to\file.dll -FromEa
Get the cached signing level from \??\c:\path\to\file.dll using the extended attribute.
#>
function Get-NtCachedSigningLevel {
    Param(
        [parameter(Position = 0, Mandatory)]
        [string]$Path,
        [switch]$Win32Path,
        [switch]$FromEa
    )

    $access = if ($FromEa) {
        [NtApiDotNet.FileAccessRights]::ReadEa
    }
    else {
        [NtApiDotNet.FileAccessRights]::ReadData
    }

    Use-NtObject($f = Get-NtFile $Path -Win32Path:$Win32Path -Access $access -ShareMode Read) {
        if ($FromEa) {
            $f.GetCachedSigningLevelFromEa();
        }
        else {
            $f.GetCachedSigningLevel()
        }
    }
}

<#
.SYNOPSIS
Adds an ACE to a security descriptor DACL.
.DESCRIPTION
This cmdlet adds a new ACE to a security descriptor DACL. This cmdlet is deprecated.
.PARAMETER SecurityDescriptor
The security descriptor to add the ACE to.
.PARAMETER Sid
The SID to add to the ACE.
.PARAMETER Name
The username to add to the ACE.
.PARAMETER KnownSid
A known SID to add to the ACE.
.PARAMETER AccessMask
The access mask for the ACE.
.PARAMETER GenericAccess
A generic access mask for the ACE.
.PARAMETER Type
The type of the ACE.
.PARAMETER Flags
The flags for the ACE.
.PARAMETER Condition
The condition string for the ACE.
.PARAMETER PassThru
Pass through the created ACE.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Add-NtSecurityDescriptorDaclAce -SecurityDescriptor $sd -Sid "S-1-1-0" -AccessMask 0x1234
Adds an access allowed ACE to the DACL for SID S-1-1-0 and mask of 0x1234
.EXAMPLE
Add-NtSecurityDescriptorDaclAce -SecurityDescriptor $sd -Sid "S-1-1-0" -AccessMask (Get-NtAccessMask -FileAccess ReadData)
Adds an access allowed ACE to the DACL for SID S-1-1-0 and mask for the file ReadData access right.
#>
function Add-NtSecurityDescriptorDaclAce {
    [CmdletBinding(DefaultParameterSetName = "FromSid")]
    Param(
        [parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [parameter(Mandatory, ParameterSetName = "FromSid")]
        [NtApiDotNet.Sid]$Sid,
        [parameter(Mandatory, ParameterSetName = "FromName")]
        [string]$Name,
        [parameter(Mandatory, ParameterSetName = "FromKnownSid")]
        [NtApiDotNet.KnownSidValue]$KnownSid,
        [NtApiDotNet.AccessMask]$AccessMask = 0,
        [NtApiDotNet.GenericAccessRights]$GenericAccess = 0,
        [NtApiDotNet.AceType]$Type = "Allowed",
        [NtApiDotNet.AceFlags]$Flags = "None",
        [string]$Condition,
        [switch]$PassThru
    )

    Write-Warning "Use Add-NtSecurityDescriptorAce instead of this."

    switch ($PSCmdlet.ParameterSetName) {
        "FromSid" {
            # Do nothing.
        }
        "FromName" {
            $Sid = Get-NtSid -Name $Name
        }
        "FromKnownSid" {
            $Sid = Get-NtSid -KnownSid $KnownSid
        }
    }

    $AccessMask = $AccessMask.Access -bor [uint32]$GenericAccess

    if ($null -ne $Sid) {
        $ace = [NtApiDotNet.Ace]::new($Type, $Flags, $AccessMask, $Sid)
        if ($Condition -ne "") {
            $ace.Condition = $Condition
        }
        $SecurityDescriptor.AddAce($ace)
        if ($PassThru) {
            Write-Output $ace
        }
    }
}

<#
.SYNOPSIS
Creates a new "fake" NT type object.
.DESCRIPTION
This cmdlet creates a new "fake" NT type object which can be used to do access checking for objects which aren't real NT types.
.PARAMETER Name
The name of the "fake" type.
.PARAMETER GenericRead
The value of GenericRead for the GENERIC_MAPPING.
.PARAMETER GenericWrite
The value of GenericWrite for the GENERIC_MAPPING.
.PARAMETER GenericExecute
The value of GenericExecute for the GENERIC_MAPPING.
.PARAMETER GenericAll
The value of GenericAll for the GENERIC_MAPPING.
.PARAMETER AccessRightsType
The enumerated type.
.INPUTS
None
.OUTPUTS
NtApiDotNet.NtType
#>
function New-NtType {
    Param(
        [parameter(Position = 0, Mandatory)]
        [string]$Name,
        [System.Type]$AccessRightsType = [NtApiDotNet.GenericAccessRights],
        [NtApiDotNet.AccessMask]$GenericRead = 0,
        [NtApiDotNet.AccessMask]$GenericWrite = 0,
        [NtApiDotNet.AccessMask]$GenericExecute = 0,
        [NtApiDotNet.AccessMask]$GenericAll = 0
    )

    [NtApiDotNet.NtType]::GetFakeType($Name, $GenericRead, $GenericWrite, $GenericExecute, $GenericAll, $AccessRightsType)
}

<#
.SYNOPSIS
Gets an ALPC server port.
.DESCRIPTION
This cmdlet gets an ALPC server port by name. As you can't directly open the server end of the port this function goes through
all handles and tries to extract the port from the hosting process. This might require elevated privileges, especially debug
privilege, to work correctly.
.PARAMETER Path
The path to the ALPC server port to get.
.PARAMETER ProcessId
The process ID of the process to query for ALPC servers.
.INPUTS
None
.OUTPUTS
NtApiDotNet.NtAlpc
.EXAMPLE
Get-NtAlpcServer
Gets all ALPC server objects accessible to the current process.
.EXAMPLE
Get-NtAlpcServer "\RPC Control\atsvc"
Gets the "\RPC Control\atsvc" ALPC server.
.EXAMPLE
Get-NtAlpcServer -ProcessId 1234
Gets all ALPC servers from PID 1234.
#>
function Get-NtAlpcServer {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromPath")]
        [string]$Path,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromProcessId")]
        [alias("pid")]
        [int]$ProcessId
    )

    if (![NtApiDotNet.NtToken]::EnableDebugPrivilege()) {
        Write-Warning "Can't enable debug privilege, results might be incomplete"
    }

    if ($PSCmdlet.ParameterSetName -ne "FromProcessId") {
        $ProcessId = -1
    }
    $hs = Get-NtHandle -ObjectTypes "ALPC Port" -ProcessId $ProcessId | Where-Object Name -ne ""

    switch ($PSCmdlet.ParameterSetName) {
        "All" {
            Write-Output $hs.GetObject()
        }
        "FromProcessId" {
            Write-Output $hs.GetObject()
        }
        "FromPath" {
            foreach ($h in $hs) {
                if ($h.Name -eq $Path) {
                    Write-Output $h.GetObject()
                    break
                }
            }
        }
    }
}

<#
.SYNOPSIS
Gets the endpoints for a RPC interface from the local endpoint mapper or by brute force.
.DESCRIPTION
This cmdlet gets the endpoints for a RPC interface from the local endpoint mapper. Not all RPC interfaces
are registered in the endpoint mapper so it might not show. You can use the -FindAlpcPort command to try
and brute force an ALPC port for the interface.
.PARAMETER InterfaceId
The UUID of the RPC interface.
.PARAMETER InterfaceVersion
The version of the RPC interface.
.PARAMETER Server
Parsed NDR server.
.PARAMETER Binding
A RPC binding string to query all endpoints from.
.PARAMETER AlpcPort
An ALPC port name. Can contain a full path as long as the string contains \RPC Control\ (case sensitive).
.PARAMETER FindAlpcPort
Use brute force to find a valid ALPC endpoint for the interface.
.INPUTS
None or NtApiDotNet.Ndr.NdrRpcServerInterface
.OUTPUTS
NtApiDotNet.Win32.RpcEndpoint[]
.EXAMPLE
Get-RpcEndpoint
Get all RPC registered RPC endpoints.
.EXAMPLE
Get-RpcEndpoint $Server
Get RPC endpoints for a parsed NDR server interface.
.EXAMPLE
Get-RpcEndpoint "A57A4ED7-0B59-4950-9CB1-E600A665154F"
Get RPC endpoints for a specified interface ID ignoring the version.
.EXAMPLE
Get-RpcEndpoint "A57A4ED7-0B59-4950-9CB1-E600A665154F" "1.0"
Get RPC endpoints for a specified interface ID and version.
.EXAMPLE
Get-RpcEndpoint "A57A4ED7-0B59-4950-9CB1-E600A665154F" "1.0" -FindAlpcPort
Get ALPC RPC endpoints for a specified interface ID and version by brute force.
.EXAMPLE
Get-RpcEndpoint -Binding "ncalrpc:[RPC_PORT]"
Get RPC endpoints for exposed over ncalrpc with name RPC_PORT.
.EXAMPLE
Get-RpcEndpoint -AlpcPort "RPC_PORT"
Get RPC endpoints for exposed over ALPC with name RPC_PORT.
#>
function Get-RpcEndpoint {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromId")]
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromIdAndVersion")]
        [string]$InterfaceId,
        [parameter(Mandatory, Position = 1, ParameterSetName = "FromIdAndVersion")]
        [Version]$InterfaceVersion,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromServer", ValueFromPipeline)]
        [NtApiDotNet.Ndr.NdrRpcServerInterface]$Server,
        [parameter(Mandatory, ParameterSetName = "FromBinding")]
        [string]$Binding,
        [parameter(Mandatory, ParameterSetName = "FromAlpc")]
        [string]$AlpcPort,
        [parameter(ParameterSetName = "FromIdAndVersion")]
        [parameter(ParameterSetName = "FromServer")]
        [switch]$FindAlpcPort
    )

    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "All" {
                [NtApiDotNet.Win32.RpcEndpointMapper]::QueryEndpoints() | Write-Output
            }
            "FromId" {
                [NtApiDotNet.Win32.RpcEndpointMapper]::QueryEndpoints($InterfaceId) | Write-Output
            }
            "FromIdAndVersion" {
                if ($FindAlpcPort) {
                    [NtApiDotNet.Win32.RpcEndpointMapper]::FindAlpcEndpointForInterface($InterfaceId, $InterfaceVersion) | Write-Output
                }
                else {
                    [NtApiDotNet.Win32.RpcEndpointMapper]::QueryEndpoints($InterfaceId, $InterfaceVersion) | Write-Output
                }
            }
            "FromServer" {
                if ($FindAlpcPort) {
                    [NtApiDotNet.Win32.RpcEndpointMapper]::FindAlpcEndpointForInterface($Server.InterfaceId, $Server.InterfaceVersion) | Write-Output
                }
                else {
                    [NtApiDotNet.Win32.RpcEndpointMapper]::QueryEndpoints($Server) | Write-Output
                }
            }
            "FromBinding" {
                [NtApiDotNet.Win32.RpcEndpointMapper]::QueryEndpointsForBinding($Binding) | Write-Output
            }
            "FromAlpc" {
                [NtApiDotNet.Win32.RpcEndpointMapper]::QueryEndpointsForAlpcPort($AlpcPort) | Write-Output
            }
        }
    }
}

<#
.SYNOPSIS
Get the RPC servers from a DLL.
.DESCRIPTION
This cmdlet parses the RPC servers from a DLL. Note that in order to parse 32 bit DLLs you must run this module in 32 bit PowerShell.
.PARAMETER FullName
The path to the DLL.
.PARAMETER DbgHelpPath
Specify path to a dbghelp DLL to use for symbol resolving. This should be ideally the dbghelp from debugging tool for Windows
which will allow symbol servers however you can use the system version if you just want to pull symbols locally.
.PARAMETER SymbolPath
Specify path for the symbols. If not specified it will first use the _NT_SYMBOL_PATH environment variable then use the
default of 'srv*https://msdl.microsoft.com/download/symbols'
.PARAMETER AsText
Return the results as text rather than objects.
.PARAMETER RemoveComments
When outputing as text remove comments from the output.
.PARAMETER ParseClients
Also parse client interface information, otherwise only servers are returned.
.PARAMETER IgnoreSymbols
Don't resolve any symbol information.
.PARAMETER SerializedPath
Path to a serialized representation of the RPC servers.
.INPUTS
string[] List of paths to DLLs.
.OUTPUTS
RpcServer[] The parsed RPC servers.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll
Get the list of RPC servers from rpcss.dll.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll -AsText
Get the list of RPC servers from rpcss.dll, return it as text.
.EXAMPLE
Get-ChildItem c:\windows\system32\*.dll | Get-RpcServer
Get the list of RPC servers from all DLLs in system32, return it as text.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll -DbgHelpPath c:\windbg\x64\dbghelp.dll
Get the list of RPC servers from rpcss.dll, specifying a different DBGHELP for symbol resolving.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll -SymbolPath c:\symbols
Get the list of RPC servers from rpcss.dll, specifying a different symbol path.
.EXAMPLE
Get-RpcServer -SerializedPath rpc.bin
Get the list of RPC servers from the serialized file rpc.bin.
#>
function Get-RpcServer {
    [CmdletBinding(DefaultParameterSetName = "FromDll")]
    Param(
        [parameter(Mandatory = $true, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = "FromDll")]
        [alias("Path")]
        [string]$FullName,
        [parameter(ParameterSetName = "FromDll")]
        [string]$DbgHelpPath,
        [parameter(ParameterSetName = "FromDll")]
        [string]$SymbolPath,
        [parameter(ParameterSetName = "FromDll")]
        [switch]$AsText,
        [parameter(ParameterSetName = "FromDll")]
        [switch]$RemoveComments,
        [parameter(ParameterSetName = "FromDll")]
        [switch]$ParseClients,
        [parameter(ParameterSetName = "FromDll")]
        [switch]$IgnoreSymbols,
        [parameter(ParameterSetName = "FromDll")]
        [switch]$ResolveStructureNames,
        [parameter(Mandatory = $true, ParameterSetName = "FromSerialized")]
        [string]$SerializedPath
    )

    BEGIN {
        if ($DbgHelpPath -eq "") {
            $DbgHelpPath = $Script:GlobalDbgHelpPath
        }
        if ($SymbolPath -eq "") {
            $SymbolPath = $env:_NT_SYMBOL_PATH
            if ($SymbolPath -eq "") {
                $SymbolPath = $Script:GlobalSymbolPath
            }
        }

        $ParserFlags = [NtApiDotNet.Win32.RpcServerParserFlags]::None
        if ($ParseClients) {
            $ParserFlags = $ParserFlags -bor [NtApiDotNet.Win32.RpcServerParserFlags]::ParseClients
        }
        if ($IgnoreSymbols) {
            $ParserFlags = $ParserFlags -bor [NtApiDotNet.Win32.RpcServerParserFlags]::IgnoreSymbols
        }
        if ($ResolveStructureNames) {
            $ParserFlags = $ParserFlags -bor [NtApiDotNet.Win32.RpcServerParserFlags]::ResolveStructureNames
        }
    }

    PROCESS {
        try {
            if ($PSCmdlet.ParameterSetName -eq "FromDll") {
                $FullName = Resolve-Path -LiteralPath $FullName -ErrorAction Stop
                Write-Progress -Activity "Parsing RPC Servers" -CurrentOperation "$FullName"
                $servers = [NtApiDotNet.Win32.RpcServer]::ParsePeFile($FullName, $DbgHelpPath, $SymbolPath, $ParserFlags)
                if ($AsText) {
                    foreach ($server in $servers) {
                        $text = $server.FormatAsText($RemoveComments)
                        Write-Output $text
                    }
                }
                else {
                    Write-Output $servers
                }
            }
            else {
                $FullName = Resolve-Path -LiteralPath $SerializedPath -ErrorAction Stop
                Use-NtObject($stm = [System.IO.File]::OpenRead($FullName)) {
                    while ($stm.Position -lt $stm.Length) {
                        [NtApiDotNet.Win32.RpcServer]::Deserialize($stm) | Write-Output
                    }
                }
            }
        }
        catch {
            Write-Error $_
        }
    }
}

<#
.SYNOPSIS
Set a list RPC servers to a file for storage.
.DESCRIPTION
This cmdlet serializes a list of RPC servers to a file. This can be restored using Get-RpcServer -SerializedPath.
.PARAMETER Path
The path to the output file.
.PARAMETER Server
The list of servers to serialize.
.INPUTS
RpcServer[] List of paths to DLLs.
.OUTPUTS
None
.EXAMPLE
Set-RpcServer -Server $server -Path rpc.bin
Serialize servers to file rpc.bin.
#>
function Set-RpcServer {
    Param(
        [parameter(Mandatory = $true, Position = 0, ValueFromPipeline)]
        [NtApiDotNet.Win32.RpcServer[]]$Server,
        [parameter(Mandatory = $true, Position = 1)]
        [string]$Path
    )

    BEGIN {
        "" | Set-Content -Path $Path
        $Path = Resolve-Path -LiteralPath $Path -ErrorAction Stop
        $stm = [System.IO.File]::Create($Path)
    }

    PROCESS {
        try {
            foreach ($s in $Server) {
                $s.Serialize($stm)
            }
        }
        catch {
            Write-Error $_
        }
    }

    END {
        $stm.Close()
    }
}

<#
.SYNOPSIS
Format the RPC servers as text.
.DESCRIPTION
This cmdlet formats a list of RPC servers as text.
.PARAMETER RpcServer
The RPC servers to format.
.PARAMETER RemoveComments
When outputing as text remove comments from the output.
.PARAMETER CppFormat
Format output in C++ pseudo syntax rather than C++.
.INPUTS
RpcServer[] The RPC servers to format.
.OUTPUTS
string[] The formatted RPC servers.
.EXAMPLE
Format-RpcServer $rpc
Format list of RPC servers in $rpc.
.EXAMPLE
Format-RpcServer $rpc -RemoveComments
Format list of RPC servers in $rpc without comments.
.EXAMPLE
Get-RpcServer c:\windows\system32\rpcss.dll | Format-RpcServer
Get the list of RPC servers from rpcss.dll and format them.
#>
function Format-RpcServer {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true, Position = 0, ValueFromPipeline)]
        [NtApiDotNet.Win32.RpcServer[]]$RpcServer,
        [switch]$RemoveComments,
        [switch]$CppFormat
    )

    PROCESS {
        foreach ($server in $RpcServer) {
            $server.FormatAsText($RemoveComments, $CppFormat) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Gets a list of ALPC RPC servers.
.DESCRIPTION
This cmdlet gets a list of ALPC RPC servers. This relies on being able to access the list of ALPC ports in side a process so might need elevated privileges.
.PARAMETER ProcessId
The ID of a process to query for ALPC servers.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.RpcAlpcServer[]
.EXAMPLE
Get-RpcAlpcServer
Get all ALPC RPC servers.
.EXAMPLE
Get-RpcAlpcServer -ProcessId 1234
Get all ALPC RPC servers in process ID 1234.
#>
function Get-RpcAlpcServer {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromProcessId")]
        [int]$ProcessId
    )

    Set-NtTokenPrivilege SeDebugPrivilege | Out-Null
    switch ($PsCmdlet.ParameterSetName) {
        "All" {
            [NtApiDotNet.Win32.RpcAlpcServer]::GetAlpcServers()
        }
        "FromProcessId" {
            [NtApiDotNet.Win32.RpcAlpcServer]::GetAlpcServers($ProcessId)
        }
    }
}

<#
.SYNOPSIS
Sets the global symbol resolver paths.
.DESCRIPTION
This cmdlet sets the global symbol resolver paths. This allows you to specify symbol resolver paths for cmdlets which support it.
.PARAMETER DbgHelpPath
Specify path to a dbghelp DLL to use for symbol resolving. This should be ideally the dbghelp from debugging tool for Windows
which will allow symbol servers however you can use the system version if you just want to pull symbols locally.
.PARAMETER SymbolPath
Specify path for the symbols.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-GlobalSymbolResolver -DbgHelpPath c:\windbg\x64\dbghelp.dll
Specify the global dbghelp path.
.EXAMPLE
Set-GlobalSymbolResolver -DbgHelpPath dbghelp.dll -SymbolPath "c:\symbols"
Specify the global dbghelp path using c:\symbols to source the symbol files.
#>
function Set-GlobalSymbolResolver {
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$DbgHelpPath,
        [parameter(Position = 1)]
        [string]$SymbolPath
    )

    $Script:GlobalDbgHelpPath = $DbgHelpPath
    if ("" -ne $SymbolPath) {
        $Script:GlobalSymbolPath = $SymbolPath
    }
}

<#
.SYNOPSIS
Gets a list of running services.
.DESCRIPTION
This cmdlet gets a list of running services. It can also include in the list non-active services.
.PARAMETER IncludeNonActive
Specify to return all services including non-active ones.
.PARAMETER Driver
Specify to include drivers.
.PARAMETER State
Specify the state of the services to get.
.PARAMETER ServiceType
Specify to filter the services to specific types only.
.PARAMETER Name
Specify names to lookup.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.RunningService[]
.EXAMPLE
Get-RunningService
Get all running services.
.EXAMPLE
Get-RunningService -IncludeNonActive
Get all services including non-active services.
.EXAMPLE
Get-RunningService -Driver
Get all running drivers.
.EXAMPLE
Get-RunningService -Name Fax
Get the Fax running service.
.EXAMPLE
Get-RunningService -State All -ServiceType UserService
Get all user services.
#>
function Get-RunningService {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(ParameterSetName = "All")]
        [switch]$IncludeNonActive,
        [parameter(ParameterSetName = "All")]
        [switch]$Driver,
        [parameter(ParameterSetName = "FromArgs")]
        [NtApiDotNet.Win32.ServiceState]$State = "Active",
        [parameter(Mandatory, ParameterSetName = "FromArgs")]
        [NtApiDotNet.Win32.ServiceType]$ServiceType = 0,
        [parameter(ParameterSetName = "FromName", Position = 0)]
        [string[]]$Name
    )

    PROCESS {
        switch ($PSCmdlet.ParameterSetName) {
            "All" {
                if ($Driver) {
                    $ServiceType = [NtApiDotNet.Win32.ServiceUtils]::GetDriverTypes()
                }
                else {
                    $ServiceType = [NtApiDotNet.Win32.ServiceUtils]::GetServiceTypes()
                }

                if ($IncludeNonActive) {
                    $State = "All"
                }
                else {
                    $State = "Active"
                }

                [NtApiDotNet.Win32.ServiceUtils]::GetServices($State, $ServiceType) | Write-Output
            }
            "FromArgs" {
                [NtApiDotNet.Win32.ServiceUtils]::GetServices($State, $ServiceType) | Write-Output
            }
            "FromName" {
                foreach ($n in $Name) {
                    [NtApiDotNet.Win32.ServiceUtils]::GetService($n) | Write-Output
                }
            }
        }
    }
}

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
NtApiDotNet.NtToken
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
        [NtApiDotNet.NtToken]$Token,
        [parameter(Mandatory, ParameterSetName = "Impersonation", Position = 0)]
        [NtApiDotNet.SecurityImpersonationLevel]$ImpersonationLevel,
        [parameter(Mandatory, ParameterSetName = "Primary")]
        [switch]$Primary,
        [NtApiDotNet.TokenAccessRights]$Access = "MaximumAllowed",
        [switch]$Inherit,
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor
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
Gets an object from a handle in the current process.
.DESCRIPTION
This cmdlet creates an object for a handle in the current process.
.PARAMETER Handle
Specify the handle in the current process.
.PARAMETER OwnsHandle
Specify the own the handle (closed when object is disposed).
.INPUTS
None
.OUTPUTS
NtApiDotNet.NtObject
.EXAMPLE
Get-NtObjectFromHandle -Handle 0x1234
Get an object from handle 0x1234.
.EXAMPLE
Get-NtObjectFromHandle -Handle 0x1234 -OwnsHandle
Get an object from handle 0x1234 and owns the handle.
#>
function Get-NtObjectFromHandle {
    Param(
        [parameter(Mandatory, Position = 0)]
        [IntPtr]$Handle,
        [switch]$OwnsHandle
    )

    $temp_handle = [NtApiDotNet.SafeKernelObjectHandle]::new($Handle, $false)
    [NtApiDotNet.NtType]::GetTypeForHandle($temp_handle, $true).FromHandle($Handle, $OwnsHandle)
}

function Test-ProcessToken {
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtApiDotNet.NtProcess]$Process,
        [parameter(Mandatory, Position = 1)]
        [NtApiDotNet.Sid]$User,
        [NtApiDotNet.TokenPrivilegeValue[]]$RequiredPrivilege,
        [NtApiDotNet.Sid[]]$RequiredGroup
    )
    Use-NtObject($token = Get-NtToken -Primary -Process $Process -Access Query -ErrorAction SilentlyContinue) {
        if ($null -eq $token) {
            return $false
        }

        if ($token.User.Sid -ne $User) {
            return $false
        }
        $privs = $token.Privileges.Name
        foreach ($priv in $RequiredPrivilege) {
            if ($priv.ToString() -notin $privs) {
                return $false
            }
        }

        $groups = $token.Groups | Where-Object Enabled
        foreach ($group in $RequiredGroup) {
            if ($group -notin $groups.Sid) {
                return $false
            }
        }
    }
    return $true
}

<#
.SYNOPSIS
Starts a new Win32 process which is a child of a process meeting a set of criteria.
.DESCRIPTION
This cmdlet starts a new Win32 process which is a child of a process meeting a set of criteria such as user account, privileges and groups. You can use this as an admin to get a system process spawned on the current desktop.
.PARAMETER CommandLine
The command line of the process to create.
.PARAMETER CreationFlags
Flags to affect process creation.
.PARAMETER TerminateOnDispose
Specify switch to terminate the process when the Win32Process object is disposed.
.PARAMETER Desktop
Optional desktop for the new process.
.PARAMETER RequiredPrivilege
Optional list of privileges the parent process must have to create the child.
.PARAMETER RequiredGroup
Optional list of groups the parent process must have to create the child.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Win32Process
.EXAMPLE
Start-Win32ChildProcess cmd.exe
Start a new child process as the system user.
.EXAMPLE
Start-Win32ChildProcess cmd.exe -User LS
Start a new child process as the local service user.
.EXAMPLE
Start-Win32ChildProcess cmd.exe -RequiredPrivilege SeAssignPrimaryTokenPrivilege
Start a new child process as the system user with SeAssignPrimaryTokenPrivilege.
.EXAMPLE
Start-Win32ChildProcess cmd.exe -RequiredGroup BA
Start a new child process as the system user with the builtin administrators group.
#>
function Start-Win32ChildProcess {
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$CommandLine,
        [NtApiDotNet.Sid]$User = "SY",
        [NtApiDotNet.TokenPrivilegeValue[]]$RequiredPrivilege,
        [NtApiDotNet.Sid[]]$RequiredGroup,
        [string]$Desktop = "WinSta0\Default",
        [NtApiDotNet.Win32.CreateProcessFlags]$CreationFlags = "NewConsole",
        [switch]$TerminateOnDispose
    )

    Set-NtTokenPrivilege SeDebugPrivilege | Out-Null

    Use-NtObject($ps = Get-NtProcess -Access QueryLimitedInformation, CreateProcess `
            -FilterScript { Test-ProcessToken $_ -User $User -RequiredPrivilege $RequiredPrivilege -RequiredGroup $RequiredGroup }) {
        $parent = $ps | Select-Object -First 1
        if ($null -eq $parent) {
            Write-Error "Couldn't find suitable process to spawn a child."
            return
        }
        New-Win32Process -CommandLine $CommandLine -Desktop $Desktop -CreationFlags $CreationFlags -ParentProcess $parent -TerminateOnDispose:$TerminateOnDispose
    }
}

<#
.SYNOPSIS
Get the values from a registry key.
.DESCRIPTION
This cmdlet will get one or more values from a registry key.
.PARAMETER Key
The base key to query the values from.
.PARAMETER Name
The name of the value to query. If not specified then returns all values.
.PARAMETER AsString
Output the values as strings.
.INPUTS
None
.OUTPUTS
NtKeyValue
.EXAMPLE
Get-NtKeyValue $key
Get all values from a key.
.EXAMPLE
Get-NtKeyValue $key -AsString
Get all values from a key as a string.
.EXAMPLE
Get-NtKeyValue $key -Name ""
Get the default value from a key.
.EXAMPLE
Get-NtKeyValue $key -Name MyValue
Get the MyValue value from a key.
#>
function Get-NtKeyValue {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtApiDotNet.NtKey]$Key,
        [parameter(ParameterSetName = "FromName", Position = 1)]
        [string]$Name,
        [switch]$AsString
    )
    $values = switch ($PSCmdlet.ParameterSetName) {
        "All" {
            $Key.QueryValues()
        }
        "FromName" {
            @($Key.QueryValue($Name))
        }
    }
    if ($AsString) {
        foreach ($v in $values) {
            $v.ToString() | Write-Output
        }
    }
    else {
        $values | Write-Output
    }
}

<#
.SYNOPSIS
Remove a value from a registry key.
.DESCRIPTION
This cmdlet will remove one more values from a registry key.
.PARAMETER Key
The base key to remove the values from.
.PARAMETER Name
The names of the values to remove.
.INPUTS
None
.EXAMPLE
Remove-NtKeyValue -Key $key -Name ABC
Removes the value ABC from the Key.
.EXAMPLE
Remove-NtKeyValue -Key $key -Name ABC, XYZ
Removes the value ABC and XYZ from the Key.
#>
function Remove-NtKeyValue {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtApiDotNet.NtKey]$Key,
        [parameter(Mandatory, Position = 1)]
        [string[]]$Name
    )
    foreach ($n in $Name) {
        $Key.DeleteValue($n)
    }
}

<#
.SYNOPSIS
Starts a file oplock with a specific level.
.DESCRIPTION
This cmdlet starts a file oplock with a specific level.
.PARAMETER File
The file to oplock on.
.PARAMETER Level
The oplock level to start.
.PARAMETER LeaseLevel
The oplock lease level to start.
.INPUTS
None
.OUTPUTS
None or NtApiDotNet.RequestOplockOutputBuffer if using LeaseLevel.
.EXAMPLE
Start-NtFileOplock $file -Exclusive
Start an exclusive oplock.
.EXAMPLE
Start-NtFileOplock $file -Level Level1
Start a level 1 oplock.
.EXAMPLE
Start-NtFileOplock $file -LeaseLevel Read,Handle
Start a "lease" oplock with Read and Handle levels.
#>
function Start-NtFileOplock {
    [CmdletBinding(DefaultParameterSetName = "OplockLevel")]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtApiDotNet.NtFile]$File,
        [parameter(Mandatory, ParameterSetName = "OplockExclusive")]
        [switch]$Exclusive,
        [parameter(Mandatory, Position = 1, ParameterSetName = "OplockLevel")]
        [NtApiDotNet.OplockRequestLevel]$Level,
        [parameter(Mandatory, ParameterSetName = "OplockLease")]
        [NtApiDotNet.OplockLevelCache]$LeaseLevel
    )

    switch ($PSCmdlet.ParameterSetName) {
        "OplockExclusive" {
            $File.OplockExclusive()
        }
        "OplockLevel" {
            $File.RequestOplock($Level)
        }
        "OplockLease" {
            $File.RequestOplockLease($LeaseLevel)
        }
    }
}

<#
.SYNOPSIS
Get a specified mitigation policy value for a process.
.DESCRIPTION
This cmdlet queries for a specific mitigation policy value from a process. The result is an enumeration or a raw value depending on the request.
.PARAMETER Process
Specify the process to query. Defaults to the current process.
.PARAMETER Policy
Specify the mitigation policy.
.PARAMETER AsRaw
Specify the query the policy as a raw integer.
.INPUTS
None
.OUTPUTS
An enumerated value or an integer.
.EXAMPLE
Get-NtProcessMitigationPolicy Signature
Query the signature mitigation policy for the current process.
.EXAMPLE
Get-NtProcessMitigationPolicy Signature -Process $p
Query the signature mitigation policy for a specified process.
.EXAMPLE
Get-NtProcessMitigationPolicy Signature -Process-AsRaw
Query the signature mitigation policy for the current process as a raw integer.
#>
function Get-NtProcessMitigationPolicy {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtApiDotNet.ProcessMitigationPolicy]$Policy,
        [parameter(ValueFromPipeline)]
        [NtApiDotNet.NtProcess]$Process,
        [switch]$AsRaw
    )

    PROCESS {
        if ($null -eq $Process) {
            $Process = Get-NtProcess -Current
        }
        if ($AsRaw) {
            $Process.GetRawMitigationPolicy($Policy) | Write-Output
        }
        else {
            $Process.GetMitigationPolicy($Policy) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Set a specified mitigation policy value for a process.
.DESCRIPTION
This cmdlet sets a specific mitigation policy value for a process. The policy value can either be an explicit enumeration or a raw value.
.PARAMETER Process
Specify the process to set. Defaults to the current process and the majority of policies can't be set externally.
.PARAMETER Policy
Specify the mitigation policy when setting a raw value.
.PARAMETER RawValue
Specify the raw value to set.
.PARAMETER ImageLoad,
Specify policy flags for image load mitigation.
.PARAMETER Signature,
Specify policy flags for signature mitigation policy.
.PARAMETER SystemCallDisable,
Specify policy flags for system call disable mitigation policy.
.PARAMETER DynamicCode,
Specify policy flags for dynamic code mitigation policy.
.PARAMETER ExtensionPointDisable,
Specify policy flags for extension point disable mitigation policy.
.PARAMETER FontDisable,
Specify policy flags for font disable mitigation policy.
.PARAMETER ControlFlowGuard,
Specify policy flags for control flow guard mitigation policy.
.PARAMETER StrictHandleCheck,
Specify policy flags for strict handle check mitigation policy.
.PARAMETER ChildProcess,
Specify policy flags for child process mitigation policy.
.PARAMETER PayloadRestriction,
Specify policy flags for payload restrictions mitigation policy.
.PARAMETER SystemCallFilter,
Specify policy flags for system call filter mitigation policy.
.PARAMETER SideChannelIsolation,
Specify policy flags for side channel isolation mitigation policy.
.PARAMETER Aslr
Specify policy flags for ASLR mitigation policy.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-NtProcessMitigationPolicy -Policy Signature -RawValue 1
Set the signature mitigation policy for the current process with a raw value of 1.
.EXAMPLE
Set-NtProcessMitigationPolicy -Signature MicrosoftSignedOnly
Set mitigation signed only signature policy for the current process.
.EXAMPLE
Set-NtProcessMitigationPolicy -Signature MicrosoftSignedOnly -Process $p
Set mitigation signed only signature policy for a specified process.
#>
function Set-NtProcessMitigationPolicy {
    [CmdletBinding()]
    Param(
        [parameter(ValueFromPipeline)]
        [NtApiDotNet.NtProcess]$Process,
        [parameter(Mandatory, ParameterSetName = "FromRaw")]
        [int]$RawValue,
        [parameter(Mandatory, ParameterSetName = "FromRaw")]
        [NtApiDotNet.ProcessMitigationPolicy]$Policy,
        [parameter(Mandatory, ParameterSetName = "FromImageLoad")]
        [NtApiDotNet.ProcessMitigationImageLoadPolicy]$ImageLoad,
        [parameter(Mandatory, ParameterSetName = "FromSignature")]
        [NtApiDotNet.ProcessMitigationBinarySignaturePolicy]$Signature,
        [parameter(Mandatory, ParameterSetName = "FromSystemCallDisable")]
        [NtApiDotNet.ProcessMitigationSystemCallDisablePolicy]$SystemCallDisable,
        [parameter(Mandatory, ParameterSetName = "FromDynamicCode")]
        [NtApiDotNet.ProcessMitigationDynamicCodePolicy]$DynamicCode,
        [parameter(Mandatory, ParameterSetName = "FromExtensionPointDisable")]
        [NtApiDotNet.ProcessMitigationExtensionPointDisablePolicy]$ExtensionPointDisable,
        [parameter(Mandatory, ParameterSetName = "FromFontDisable")]
        [NtApiDotNet.ProcessMitigationFontDisablePolicy]$FontDisable,
        [parameter(Mandatory, ParameterSetName = "FromControlFlowGuard")]
        [NtApiDotNet.ProcessMitigationControlFlowGuardPolicy]$ControlFlowGuard,
        [parameter(Mandatory, ParameterSetName = "FromStrictHandleCheck")]
        [NtApiDotNet.ProcessMitigationStrictHandleCheckPolicy]$StrictHandleCheck,
        [parameter(Mandatory, ParameterSetName = "FromChildProcess")]
        [NtApiDotNet.ProcessMitigationChildProcessPolicy]$ChildProcess,
        [parameter(Mandatory, ParameterSetName = "FromPayloadRestriction")]
        [NtApiDotNet.ProcessMitigationPayloadRestrictionPolicy]$PayloadRestriction,
        [parameter(Mandatory, ParameterSetName = "FromSystemCallFilter")]
        [NtApiDotNet.ProcessMitigationSystemCallFilterPolicy]$SystemCallFilter,
        [parameter(Mandatory, ParameterSetName = "FromSideChannelIsolation")]
        [NtApiDotNet.ProcessMitigationSideChannelIsolationPolicy]$SideChannelIsolation,
        [parameter(Mandatory, ParameterSetName = "FromAslr")]
        [NtApiDotNet.ProcessMitigationAslrPolicy]$Aslr
    )

    BEGIN {
        $Value = 0
        $FromRaw = $false
        switch ($PsCmdlet.ParameterSetName) {
            "FromRaw" { $Value = $RawValue; $FromRaw = $true }
            "FromImageLoad" { $Policy = "ImageLoad"; $Value = $ImageLoad }
            "FromSignature" { $Policy = "Signature"; $Value = $Signature }
            "FromSystemCallDisable" { $Policy = "SystemCallDisable"; $Value = $SystemCallDisable }
            "FromDynamicCode" { $Policy = "DynamicCode"; $Value = $DynamicCode }
            "FromExtensionPointDisable" { $Policy = "ExtensionPointDisable"; $Value = $ExtensionPointDisable }
            "FromFontDisable" { $Policy = "FontDisable"; $Value = $FontDisable }
            "FromControlFlowGuard" { $Policy = "ControlFlowGuard"; $Value = $ControlFlowGuard }
            "FromStrictHandleCheck" { $Policy = "StrictHandleCheck"; $Value = $StrictHandleCheck }
            "FromChildProcess" { $Policy = "ChildProcess"; $Value = $ChildProcess }
            "FromPayloadRestriction" { $Policy = "PayloadRestriction"; $Value = $PayloadRestriction }
            "FromSystemCallFilter" { $Policy = "SystemCallFilter"; $Value = $SystemCallFilter }
            "FromSideChannelIsolation" { $Policy = "SideChannelIsolation"; $Value = $SideChannelIsolation }
            "FromAslr" { $Policy = "ASLR"; $Value = $Aslr }
        }
    }

    PROCESS {
        if ($null -eq $Process) {
            $Process = Get-NtProcess -Current
        }

        if ($FromRaw) {
            $Process.SetRawMitigationPolicy($Policy, $Value)
        }
        else {
            $Process.SetMitigationPolicy($Policy, $Value)
        }
    }
}

<#
.SYNOPSIS
Get an appcontainer profile for a specified package name.
.DESCRIPTION
This cmdlet gets an appcontainer profile for a specified package name.
.PARAMETER Name
Specify appcontainer name to use for the profile.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.AppContainerProfile
.EXAMPLE
Get-AppContainerProfile
Get appcontainer profiles for all installed packages.
.EXAMPLE
Get-AppContainerProfile -Name Package_aslkjdskjds
Get an appcontainer profile from a package name.
#>
function Get-AppContainerProfile {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [parameter(ParameterSetName = "All")]
        [switch]$AllUsers,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromName", ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string]$Name
    )

    PROCESS {
        switch ($PSCmdlet.ParameterSetName) {
            "All" {
                Get-AppxPackage | Select-Object @{Name = "Name"; Expression = { "$($_.Name)_$($_.PublisherId)" } } | Get-AppContainerProfile
            }
            "FromName" {
                [NtApiDotNet.Win32.AppContainerProfile]::Open($Name) | Write-Output
            }
        }
    }
}

<#
.SYNOPSIS
Create a new appcontainer profile for a specified package name.
.DESCRIPTION
This cmdlet create a new appcontainer profile for a specified package name. If the profile already exists it'll open it.
.PARAMETER Name
Specify appcontainer name to use for the profile.
.PARAMETER DisplayName
Specify the profile display name.
.PARAMETER Description
Specify the profile description.
.PARAMETER DeleteOnClose
Specify the profile should be deleted when closed.
.PARAMETER TemporaryProfile
Specify to create a temporary profile. Close the profile after use to delete it.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.AppContainerProfile
.EXAMPLE
New-AppContainerProfile -Name Package_aslkjdskjds
Create a new AppContainer profile with a specified name.
.EXAMPLE
Get-AppContainerProfile -TemporaryProfile
Create a new temporary profile.
#>
function New-AppContainerProfile {
    [CmdletBinding(DefaultParameterSetName = "FromName")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromName")]
        [string]$Name,
        [parameter(Position = 1, ParameterSetName = "FromName")]
        [string]$DisplayName = "DisplayName",
        [parameter(Position = 2, ParameterSetName = "FromName")]
        [string]$Description = "Description",
        [parameter(ParameterSetName = "FromName")]
        [NtApiDotNet.Sid[]]$Capabilities,
        [parameter(ParameterSetName = "FromName")]
        [switch]$DeleteOnClose,
        [parameter(Mandatory, ParameterSetName = "FromTemp")]
        [switch]$TemporaryProfile
    )

    switch ($PSCmdlet.ParameterSetName) {
        "FromName" {
            $prof = [NtApiDotNet.Win32.AppContainerProfile]::Create($Name, $DisplayName, $Description, $Capabilities)
            if ($null -ne $prof) {
                $prof.DeleteOnClose = $DeleteOnClose
                Write-Output $prof
            }
        }
        "FromTemp" {
            [NtApiDotNet.Win32.AppContainerProfile]::CreateTemporary() | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get a RPC client object based on a parsed RPC server.
.DESCRIPTION
This cmdlet creates a new RPC client from a parsed RPC server. The client object contains methods
to call RPC methods. The client starts off disconnected. You need to pass the client to Connect-RpcClient to
connect to the server. If you specify an interface ID and version then a generic client will be created which
allows simple calls to be made without requiring the NDR data.
.PARAMETER Server
Specify the RPC server to base the client on.
.PARAMETER NamespaceName
Specify the name of the compiled namespace for the client.
.PARAMETER ClientName
Specify the class name of the compiled client.
.PARAMETER IgnoreCache
Specify to ignore the compiled client cache and regenerate the source code.
.PARAMETER InterfaceId
Specify the interface ID for a generic client.
.PARAMETER InterfaceVersion
Specify the interface version for a generic client.
.PARAMETER Provider
Specify a Code DOM provider. Defaults to C#.
.PARAMETER Flags
Specify optional flags for the built client class.
.PARAMETER EnableDebugging
Specify to enable debugging on the compiled code.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Rpc.RpcClientBase
.EXAMPLE
Get-RpcClient -Server $Server
Create a new RPC client from a parsed RPC server.
#>
function Get-RpcClient {
    [CmdletBinding(DefaultParameterSetName = "FromServer")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromServer", ValueFromPipeline)]
        [NtApiDotNet.Win32.RpcServer]$Server,
        [parameter(ParameterSetName = "FromServer")]
        [string]$NamespaceName,
        [parameter(ParameterSetName = "FromServer")]
        [string]$ClientName,
        [parameter(ParameterSetName = "FromServer")]
        [switch]$IgnoreCache,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromIdAndVersion")]
        [string]$InterfaceId,
        [parameter(Mandatory, Position = 1, ParameterSetName = "FromIdAndVersion")]
        [Version]$InterfaceVersion,
        [parameter(ParameterSetName = "FromServer")]
        [System.CodeDom.Compiler.CodeDomProvider]$Provider,
        [parameter(ParameterSetName = "FromServer")]
        [NtApiDotNet.Win32.Rpc.RpcClientBuilderFlags]$Flags = "GenerateConstructorProperties, StructureReturn, HideWrappedMethods, UnsignedChar, NoNamespace",
        [switch]$EnableDebugging
    )

    BEGIN {
        if (Get-IsPSCore) {
            if ($null -ne $Provider) {
                Write-Warning "PowerShell Core doesn't support arbitrary providers. Using in-built C#."
            }
            $Provider = New-Object NtObjectManager.Utils.CoreCSharpCodeProvider
        }
    }

    PROCESS {
        if ($PSCmdlet.ParameterSetName -eq "FromServer") {
            $args = [NtApiDotNet.Win32.Rpc.RpcClientBuilderArguments]::new();
            $args.NamespaceName = $NamespaceName
            $args.ClientName = $ClientName
            $args.Flags = $Flags
            $args.EnableDebugging = $EnableDebugging

            [NtApiDotNet.Win32.Rpc.RpcClientBuilder]::CreateClient($Server, $args, $IgnoreCache, $Provider)
        }
        else {
            [NtApiDotNet.Win32.RpcClient]::new($InterfaceId, $InterfaceVersion)
        }
    }
}

<#
.SYNOPSIS
Connects a RPC client to an endpoint.
.DESCRIPTION
This cmdlet connects a RPC client to an endpoint. You can specify what transport to use based on the protocol sequence.
.PARAMETER Client
Specify the RPC client to connect.
.PARAMETER ProtocolSequence
Specify the RPC protocol sequence this client will connect through.
.PARAMETER EndpointPath
Specify the endpoint string. If not specified this will lookup the endpoint from the endpoint mapper.
.PARAMETER SecurityQualityOfService
Specify the security quality of service for the connection.
.PARAMETER PassThru
Specify to the pass the client object to the output.
.PARAMETER FindAlpcPort
Specify to search for an ALPC port for the RPC client.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Connect-RpcClient -Client $Client
Connect an RPC ALPC client, looking up the path using the endpoint mapper.
.EXAMPLE
Connect-RpcClient -Client $Client -EndpointPath "\RPC Control\ABC"
Connect an RPC ALPC client with an explicit path.
.EXAMPLE
Connect-RpcClient -Client $Client -SecurityQualityOfService $(New-NtSecurityQualityOfService -ImpersonationLevel Anonymous)
Connect an RPC ALPC client with anonymous impersonation level.
.EXAMPLE
Connect-RpcClient -Client $Client -ProtocolSequence "ncalrpc"
Connect an RPC ALPC client from a specific protocol sequence.
.EXAMPLE
Connect-RpcClient -Client $Client -Endpoint $ep
Connect an RPC client to a specific endpoint.
.EXAMPLE
Connect-RpcClient -Client $Client -FindAlpcPort
Connect an RPC ALPC client, looking up the path using brute force.
#>
function Connect-RpcClient {
    [CmdletBinding(DefaultParameterSetName = "FromProtocol")]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtApiDotNet.Win32.Rpc.RpcClientBase]$Client,
        [parameter(Position = 1, ParameterSetName = "FromProtocol")]
        [string]$EndpointPath,
        [parameter(ParameterSetName = "FromProtocol")]
        [string]$ProtocolSequence = "ncalrpc",
        [parameter(Position = 1, Mandatory, ParameterSetName = "FromEndpoint")]
        [NtApiDotNet.Win32.RpcEndpoint]$Endpoint,
        [parameter(Mandatory, ParameterSetName = "FromFindEndpoint")]
        [switch]$FindAlpcPort,
        [NtApiDotNet.SecurityQualityOfService]$SecurityQualityOfService,
        [switch]$PassThru
    )

    PROCESS {
        switch ($PSCmdlet.ParameterSetName) {
            "FromProtocol" {
                $Client.Connect($ProtocolSequence, $EndpointPath, $SecurityQualityOfService)
            }
            "FromEndpoint" {
                $Client.Connect($Endpoint, $SecurityQualityOfService)
            }
            "FromFindEndpoint" {
                foreach ($ep in $(Get-ChildItem "NtObject:\RPC Control")) {
                    try {
                        $name = $ep.Name
                        Write-Progress -Activity "Finding ALPC Endpoint" -CurrentOperation "$name"
                        $Client.Connect("ncalrpc", $name, $SecurityQualityOfService)
                    }
                    catch {
                        Write-Information $_
                    }
                }
            }
        }

        if ($PassThru) {
            $Client | Write-Output
        }
    }
}

<#
.SYNOPSIS
Format a RPC client as source code based on a parsed RPC server.
.DESCRIPTION
This cmdlet gets source code for a RPC client from a parsed RPC server.
.PARAMETER Server
Specify the RPC server to base the client on.
.PARAMETER NamespaceName
Specify the name of the compiled namespace for the client.
.PARAMETER ClientName
Specify the class name of the compiled client.
.PARAMETER Flags
Specify to flags for the source creation.
.PARAMETER Provider
Specify a Code DOM provider. Defaults to C#.
.PARAMETER Options
Specify optional options for the code generation if Provider is also specified.
.PARAMETER OutputPath
Specify optional output directory to write formatted client.
.PARAMETER GroupByName
Specify when outputting to a directory to group by the name of the server executable.
.INPUTS
None
.OUTPUTS
string
.EXAMPLE
Format-RpcClient -Server $Server
Get the source code for a RPC client from a parsed RPC server.
.EXAMPLE
$servers | Format-RpcClient
Get the source code for RPC clients from a list of parsed RPC servers.
.EXAMPLE
$servers | Format-RpcClient -OutputPath rpc_output
Get the source code for RPC clients from a list of parsed RPC servers and output as separate source code files.
#>
function Format-RpcClient {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtApiDotNet.Win32.RpcServer[]]$Server,
        [string]$NamespaceName,
        [string]$ClientName,
        [NtApiDotNet.Win32.Rpc.RpcClientBuilderFlags]$Flags = 0,
        [System.CodeDom.Compiler.CodeDomProvider]$Provider,
        [System.CodeDom.Compiler.CodeGeneratorOptions]$Options,
        [string]$OutputPath,
        [switch]$GroupByName
    )

    BEGIN {
        $file_ext = "cs"
        if ($null -ne $Provider) {
            $file_ext = $Provider.FileExtension
        }

        if ("" -ne $OutputPath) {
            mkdir $OutputPath -ErrorAction Ignore | Out-Null
        }
    }

    PROCESS {
        $args = [NtApiDotNet.Win32.Rpc.RpcClientBuilderArguments]::new();
        $args.NamespaceName = $NamespaceName
        $args.ClientName = $ClientName
        $args.Flags = $Flags

        foreach ($s in $Server) {
            $src = if ($null -eq $Provider) {
                [NtApiDotNet.Win32.Rpc.RpcClientBuilder]::BuildSource($s, $args)
            }
            else {
                [NtApiDotNet.Win32.Rpc.RpcClientBuilder]::BuildSource($s, $args, $Provider, $Options)
            }

            if ("" -eq $OutputPath) {
                $src | Write-Output
            }
            else {
                if ($GroupByName) {
                    $path = Join-Path -Path $OutputPath -ChildPath $s.Name.ToLower()
                    mkdir $path -ErrorAction Ignore | Out-Null
                } else {
                    $path = $OutputPath
                }
                $path = Join-Path -Path $path -ChildPath "$($s.InterfaceId)_$($s.InterfaceVersion).$file_ext"
                $src | Set-Content -Path $path
            }
        }
    }
}

<#
.SYNOPSIS
Format RPC complex types to an encoder/decoder source code file.
.DESCRIPTION
This cmdlet gets source code for encoding and decoding RPC complex types.
.PARAMETER ComplexType
Specify the list of complex types to format.
.PARAMETER Server
Specify the server containing the list of complex types to format.
.PARAMETER NamespaceName
Specify the name of the compiled namespace for the client.
.PARAMETER EncoderName
Specify the class name of the encoder.
.PARAMETER DecoderName
Specify the class name of the decoder.
.PARAMETER Provider
Specify a Code DOM provider. Defaults to C#.
.PARAMETER Options
Specify optional options for the code generation if Provider is also specified.
.PARAMETER Pointer
Specify to always wrap complex types in an unique pointer.
.INPUTS
None
.OUTPUTS
string
.EXAMPLE
Format-RpcComplexType -Server $Server
Get the source code for RPC complex types client from a parsed RPC server.
.EXAMPLE
Format-RpcComplexType -ComplexType $ComplexTypes
Get the source code for RPC complex types client from a list of types.
#>
function Format-RpcComplexType {
    [CmdletBinding(DefaultParameterSetName = "FromTypes")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromTypes")]
        [NtApiDotNet.Ndr.NdrComplexTypeReference[]]$ComplexType,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromServer")]
        [NtApiDotNet.Win32.RpcServer]$Server,
        [string]$NamespaceName,
        [string]$EncoderName,
        [string]$DecoderName,
        [System.CodeDom.Compiler.CodeDomProvider]$Provider,
        [System.CodeDom.Compiler.CodeGeneratorOptions]$Options,
        [switch]$Pointer
    )

    PROCESS {
        $types = switch ($PsCmdlet.ParameterSetName) {
            "FromTypes" { $ComplexType }
            "FromServer" { $Server.ComplexTypes }
        }
        if ($null -eq $Provider) {
            [NtApiDotNet.Win32.Rpc.RpcClientBuilder]::BuildSource([NtApiDotNet.Ndr.NdrComplexTypeReference[]]$types, $EncoderName, $DecoderName, $NamespaceName, $Pointer) | Write-Output
        }
        else {
            [NtApiDotNet.Win32.Rpc.RpcClientBuilder]::BuildSource([NtApiDotNet.Ndr.NdrComplexTypeReference[]]$types, $EncoderName, $DecoderName, $NamespaceName, $Pointer, $Provider, $Options) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get a new RPC context handle.
.DESCRIPTION
This cmdlet creates a new RPC context handle for calling RPC APIs.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Ndr.NdrContextHandle
.EXAMPLE
New-RpcContextHandle
Creates a new RPC context handle.
#>
function New-RpcContextHandle {
    New-Object "NtApiDotNet.Ndr.NdrContextHandle"
}

<#
.SYNOPSIS
Open a file using the Win32 CreateFile API.
.DESCRIPTION
This cmdlet opens a file using the Win32 CreateFile API rather than the native APIs.
.PARAMETER Path
Specify the path to open. Note that the function doesn't resolve relative paths from the PS working directory.
.PARAMETER DesiredAccess
Specify the desired access for the handle.
.PARAMETER ShareMode
Specify the share mode for the file.
.PARAMETER SecurityDescriptor
Specify an optional security descriptor.
.PARAMETER InheritHandle
Specify that the file handle should be inheritable.
.PARAMETER Disposition
Specify the file open disposition.
.PARAMETER FlagsAndAttributes
Specify flags and attributes for the open.
.PARAMETER TemplateFile
Specify a template file to copy certain properties from.
.INPUTS
None
.OUTPUTS
NtApiDotNet.NtFile
.EXAMPLE
Get-Win32File -Path c:\abc\xyz.txt
Open the existing file c:\abc\xyz.txt
#>
function Get-Win32File {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]$Path,
        [NtApiDotNet.FileAccessRights]$DesiredAccess = "MaximumAllowed",
        [NtApiDotNet.FileShareMode]$ShareMode = 0,
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [switch]$InheritHandle,
        [NtApiDotNet.Win32.CreateFileDisposition]$Disposition = "OpenExisting",
        [NtApiDotNet.Win32.CreateFileFlagsAndAttributes]$FlagsAndAttributes = 0,
        [NtApiDotNet.NtFile]$TemplateFile
    )

    [NtApiDotNet.Win32.Win32Utils]::CreateFile($Path, $DesiredAccess, $ShareMode, `
            $SecurityDescriptor, $InheritHandle, $Disposition, $FlagsAndAttributes, $TemplateFile)
}

<#
.SYNOPSIS
Close an object handle.
.DESCRIPTION
This cmdlet closes an object handle. It supports closing a handle locally or in another process as long
as duplicate handle access is granted.
.PARAMETER Object
Specify the object to close.
.PARAMETER Process
Specify the process where the handle to close is located.
.PARAMETER ProcessId
Specify the process ID where the handle to close is located.
.PARAMETER Handle
Specify the handle value to close in another process.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Close-NtObject -Object $obj
Close an object in the current process.
.EXAMPLE
Close-NtObject -Handle 0x1234 -Process $proc
Close handle 0x1234 in another process.
.EXAMPLE
Close-NtObject -Handle 0x1234 -ProcessId 684
Close handle 0x1234 in process with ID 684.
.EXAMPLE
Close-NtObject -Handle 0x1234
Close handle 0x1234 in process the current process.
#>
function Close-NtObject {
    [CmdletBinding(DefaultParameterSetName = "FromProcess")]
    Param(
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromObject")]
        [NtApiDotNet.NtObject]$Object,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromProcess")]
        [NtApiDotNet.NtProcess]$Process,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromProcessId")]
        [int]$ProcessId,
        [parameter(Mandatory, Position = 1, ParameterSetName = "FromProcess")]
        [parameter(Mandatory, Position = 1, ParameterSetName = "FromProcessId")]
        [parameter(Mandatory, Position = 1, ParameterSetName = "FromCurrentProcess")]
        [IntPtr]$Handle,
        [parameter(Mandatory, ParameterSetName = "FromCurrentProcess")]
        [switch]$CurrentProcess
    )

    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "FromObject" { $Object.Close() }
            "FromProcess" { [NtApiDotNet.NtObject]::CloseHandle($Process, $Handle) }
            "FromProcessId" { [NtApiDotNet.NtObject]::CloseHandle($ProcessId, $Handle) }
            "FromCurrentProcess" { [NtApiDotNet.NtObject]::CloseHandle($Handle) }
        }
    }
}

<#
.SYNOPSIS
Start an accessible scheduled task.
.DESCRIPTION
This cmdlet starts a scheduled task based on an accessible task result.
.PARAMETER Task
Specify the task to start.
.PARAMETER User
Specify the user to run the task under. Can be a username or a SID.
.PARAMETER Flags
Specify optional flags.
.PARAMETER SessionId
Specify an optional session ID.
.PARAMETER Arguments
Specify optional arguments to the pass to the task.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Start-AccessibleScheduledTask -Task $task
Start a task with no options.
.EXAMPLE
Start-AccessibleScheduledTask -Task $task -Arguments "A", B"
Start a task with optional argument strings "A" and "B"
#>
function Start-AccessibleScheduledTask {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [NtObjectManager.Cmdlets.Accessible.ScheduledTaskAccessCheckResult]$Task,
        [string]$User,
        [NtObjectManager.Cmdlets.Accessible.TaskRunFlags]$Flags = 0,
        [int]$SessionId,
        [string[]]$Arguments
    )

    $Task.RunEx($Flags, $SessionId, $User, $Arguments)
}

<#
.SYNOPSIS
Get the EA buffer from a file.
.DESCRIPTION
This cmdlet queries for the Extended Attribute buffer from a file by path or from a NtFile object.
.PARAMETER Path
NT path to file.
.PARAMETER Win32Path
Specify Path is a Win32 path.
.PARAMETER File
Specify an existing NtFile object.
.INPUTS
None
.OUTPUTS
NtApiDotNet.EaBuffer
#>
function Get-NtEaBuffer {
    [CmdletBinding(DefaultParameterSetName = "FromPath")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromPath")]
        [string]$Path,
        [Parameter(ParameterSetName = "FromPath")]
        [switch]$Win32Path,
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromFile")]
        [NtApiDotNet.NtFile]$File
    )

    switch ($PsCmdlet.ParameterSetName) {
        "FromFile" {
            $File.GetEa()
        }
        "FromPath" {
            Use-NtObject($f = Get-NtFile -Path $Path -Win32Path:$Win32Path -Access ReadEa) {
                $f.GetEa()
            }
        }
    }
}

<#
.SYNOPSIS
Set the EA buffer on a file.
.DESCRIPTION
This cmdlet sets the Extended Attribute buffer on a file by path or a NtFile object.
.PARAMETER Path
NT path to file.
.PARAMETER Win32Path
Specify Path is a Win32 path.
.PARAMETER File
Specify an existing NtFile object.
.PARAMETER EaBuffer
Specify the EA buffer to set.
.INPUTS
None
.OUTPUTS
None
#>
function Set-NtEaBuffer {
    [CmdletBinding(DefaultParameterSetName = "FromPath")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromPath")]
        [string]$Path,
        [Parameter(ParameterSetName = "FromPath")]
        [switch]$Win32Path,
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromFile")]
        [NtApiDotNet.NtFile]$File,
        [Parameter(Mandatory = $true, Position = 1)]
        [NtApiDotNet.EaBuffer]$EaBuffer
    )

    switch ($PsCmdlet.ParameterSetName) {
        "FromFile" {
            $File.SetEa($EaBuffer)
        }
        "FromPath" {
            Use-NtObject($f = Get-NtFile -Path $Path -Win32Path:$Win32Path -Access WriteEa) {
                $f.SetEa($EaBuffer)
            }
        }
    }
}

<#
.SYNOPSIS
Suspend a process.
.DESCRIPTION
This cmdlet suspends a process.
.PARAMETER Process
The process to suspend.
.INPUTS
NtApiDotNet.NtProcess
.OUTPUTS
None
#>
function Suspend-NtProcess {
    [CmdletBinding(DefaultParameterSetName = "FromProcess")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromProcess", ValueFromPipeline)]
        [NtApiDotNet.NtProcess[]]$Process
    )

    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "FromProcess" {
                foreach ($p in $Process) {
                    $p.Suspend()
                }
            }
        }
    }
}

<#
.SYNOPSIS
Resume a process.
.DESCRIPTION
This cmdlet resumes a process.
.PARAMETER Process
The process to resume.
.INPUTS
NtApiDotNet.NtProcess
.OUTPUTS
None
#>
function Resume-NtProcess {
    [CmdletBinding(DefaultParameterSetName = "FromProcess")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromProcess", ValueFromPipeline)]
        [NtApiDotNet.NtProcess[]]$Process
    )

    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "FromProcess" {
                foreach ($p in $Process) {
                    $p.Resume()
                }
            }
        }
    }
}

<#
.SYNOPSIS
Stop a process.
.DESCRIPTION
This cmdlet stops/kills a process with an optional status code.
.PARAMETER Process
The process to stop.
.PARAMETER ExitCode
The NTSTATUS exit code.
.PARAMETER ExitCodeInt
The exit code as an integer.
.INPUTS
NtApiDotNet.NtProcess
.OUTPUTS
None
#>
function Stop-NtProcess {
    [CmdletBinding(DefaultParameterSetName = "FromStatus")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline)]
        [NtApiDotNet.NtProcess[]]$Process,
        [Parameter(Position = 1, ParameterSetName = "FromStatus")]
        [NtApiDotNet.NtStatus]$ExitStatus = 0,
        [Parameter(Position = 1, ParameterSetName = "FromInt")]
        [int]$ExitCode = 0
    )

    PROCESS {
        foreach ($p in $Process) {
            switch ($PsCmdlet.ParameterSetName) {
                "FromStatus" { $p.Terminate($ExitStatus) }
                "FromInt" { $p.Terminate($ExitCode) }
            }
        }
    }
}

<#
.SYNOPSIS
Suspend a thread.
.DESCRIPTION
This cmdlet suspends a thread.
.PARAMETER Process
The thread to suspend.
.INPUTS
NtApiDotNet.NtThread
.OUTPUTS
None
#>
function Suspend-NtThread {
    [CmdletBinding(DefaultParameterSetName = "FromThread")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromThread", ValueFromPipeline)]
        [NtApiDotNet.NtThread[]]$Thread
    )

    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "FromThread" {
                foreach ($t in $Thread) {
                    $t.Suspend() | Out-Null
                }
            }
        }
    }
}

<#
.SYNOPSIS
Resume a thread.
.DESCRIPTION
This cmdlet resumes a thread.
.PARAMETER Process
The thread to resume.
.INPUTS
NtApiDotNet.NtThread
.OUTPUTS
None
#>
function Resume-NtThread {
    [CmdletBinding(DefaultParameterSetName = "FromThread")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromThread", ValueFromPipeline)]
        [NtApiDotNet.NtThread[]]$Thread
    )

    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "FromThread" {
                foreach ($t in $Thread) {
                    $t.Resume() | Out-Null
                }
            }
        }
    }
}

<#
.SYNOPSIS
Stop a thread.
.DESCRIPTION
This cmdlet stops/kills a thread with an optional status code.
.PARAMETER Process
The thread to stop.
.INPUTS
NtApiDotNet.NtThread
.OUTPUTS
None
#>
function Stop-NtThread {
    [CmdletBinding(DefaultParameterSetName = "FromThread")]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "FromThread", ValueFromPipeline)]
        [NtApiDotNet.NtThread[]]$Thread,
        [NtApiDotNet.NtStatus]$ExitCode = 0
    )

    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "FromThread" {
                foreach ($t in $Thread) {
                    $t.Terminate($ExitCode)
                }
            }
        }
    }
}

<#
.SYNOPSIS
Gets a new Locally Unique ID (LUID)
.DESCRIPTION
This cmdlet requests a new LUID value.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Luid
.EXAMPLE
Get-NtLocallyUniqueId
Get a new locally unique ID.
#>
function Get-NtLocallyUniqueId {
    [NtApiDotNet.NtSystemInfo]::AllocateLocallyUniqueId() | Write-Output
}

<#
.SYNOPSIS
Get the names of the Windows Stations in the current Session.
.DESCRIPTION
This cmdlet queries the names of the Window Stations in the current Session.
.PARAMETER Current
Show the current Window Station name only.
.INPUTS
string
.OUTPUTS
None
#>
function Get-NtWindowStationName {
    Param(
        [Parameter()]
        [switch]$Current
    )

    if ($Current) {
        [NtApiDotNet.NtWindowStation]::Current.Name | Write-Output
    }
    else {
        [NtApiDotNet.NtWindowStation]::WindowStations | Write-Output
    }
}

<#
.SYNOPSIS
Gets the names of the Desktops from the specified Window Station.
.DESCRIPTION
This cmdlet queries the names of the Desktops from the specified Window Station.
By default will use the current process Window Station.
.PARAMETER WindowStation
The Window Station to query.
.PARAMETER Current
Specify to get the name of the current thread desktop.
.PARAMETER ThreadId
Specify to get the name of the desktop from a thread.
.INPUTS
string
.OUTPUTS
None
#>
function Get-NtDesktopName {
    [CmdletBinding(DefaultParameterSetName = "FromCurrentWindowStation")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromWindowStation")]
        [NtApiDotNet.NtWindowStation]$WindowStation,
        [Parameter(ParameterSetName = "FromCurrentDesktop")]
        [switch]$Current,
        [Parameter(ParameterSetName = "FromThreadId")]
        [alias("tid")]
        [int]$ThreadId
    )

    switch ($PSCmdlet.ParameterSetName) {
        "FromCurrentWindowStation" {
            $winsta = [NtApiDotNet.NtWindowStation]::Current
            $winsta.Desktops | Write-Output
        }
        "FromWindowStation" {
            $WindowStation.Desktops | Write-Output
        }
        "FromCurrentDesktop" {
            [NtApiDotNet.NtDesktop]::Current.Name | Write-Output
        }
        "FromThreadId" {
            [NtApiDotNet.NtDesktop]::GetThreadDesktop($ThreadId).Name | Write-Output
        }
    }
}

<#
.SYNOPSIS
Gets the a list of Window handles.
.DESCRIPTION
This cmdlet queries the list of Window Handles based on a set of criteria such as Desktop or ThreadId.
.PARAMETER Desktop
The Desktop to query.
.PARAMETER Parent
Specify the parent Window if enumerating children.
.PARAMETER Children
Specify the get list of child windows.
.PARAMETER Immersive
Specify to get immersive Windows.
.PARAMETER ThreadId
Specify the thread ID for the Window.
.PARAMETER ProcessId
Specify the process ID for the Window.
.INPUTS
None
.OUTPUTS
NtApiDotNet.NtWindow
#>
function Get-NtWindow {
    [CmdletBinding()]
    Param(
        [NtApiDotNet.NtDesktop]$Desktop,
        [switch]$Children,
        [switch]$Immersive,
        [NtApiDotNet.NtWindow]$Parent = [NtApiDotNet.NtWindow]::Null,
        [alias("tid")]
        [int]$ThreadId,
        [alias("pid")]
        [int]$ProcessId
    )

    $ws = [NtApiDotNet.NtWindow]::GetWindows($Desktop, $Parent, $Children, !$Immersive, $ThreadId)
    if ($ProcessId -ne 0) {
         $ws = $ws | Where-Object ProcessId -eq $ProcessId
    }
    $ws | Write-Output
}

<#
.SYNOPSIS
Outputs a hex dump for a byte array.
.DESCRIPTION
This cmdlet converts a byte array to a hex dump.
.PARAMETER Bytes
The bytes to convert.
.PARAMETER ShowHeader
Display a header for the hex dump.
.PARAMETER ShowAddress
Display the address for the hex dump.
.PARAMETER ShowAscii
Display the ASCII dump along with the hex.
.PARAMETER HideRepeating
Hide repeating 16 byte patterns.
.PARAMETER Buffer
Show the contents of a safe buffer.
.PARAMETER Offset
Specify start offset into the safe buffer.
.PARAMETER Length
Specify length of safe buffer.
.PARAMETER BaseAddress
Specify base address for the display when ShowAddress is enabled.
.INPUTS
byte[]
.OUTPUTS
String
#>
function Out-HexDump {
    [CmdletBinding(DefaultParameterSetName = "FromBytes")]
    Param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ParameterSetName = "FromBytes")]
        [byte[]]$Bytes,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromBuffer")]
        [System.Runtime.InteropServices.SafeBuffer]$Buffer,
        [Parameter(ParameterSetName = "FromBuffer")]
        [int64]$Offset = 0,
        [Parameter(ParameterSetName = "FromBuffer")]
        [int64]$Length = 0,
        [Parameter(ParameterSetName = "FromBytes")]
        [int64]$BaseAddress = 0,
        [switch]$ShowHeader,
        [switch]$ShowAddress,
        [switch]$ShowAscii,
        [switch]$ShowAll,
        [switch]$HideRepeating
    )

    BEGIN {
        if ($ShowAll) {
            $ShowHeader = $true
            $ShowAscii = $true
            $ShowAddress = $true
        }
        switch ($PsCmdlet.ParameterSetName) {
            "FromBytes" {
                $builder = [NtApiDotNet.Utilities.Text.HexDumpBuilder]::new($ShowHeader, $ShowAddress, $ShowAscii, $HideRepeating, $BaseAddress);
            }
            "FromBuffer" {
                $builder = [NtApiDotNet.Utilities.Text.HexDumpBuilder]::new($Buffer, $Offset, $Length, $ShowHeader, $ShowAddress, $ShowAscii, $HideRepeating);
            }
        }
    }

    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "FromBytes" {
                $builder.Append($Bytes)
            }
        }
    }

    END {
        $builder.Complete()
        $builder.ToString() | Write-Output
    }
}

<#
.SYNOPSIS
Gets the access masks for a type.
.DESCRIPTION
This cmdlet gets the access masks for a type.
.PARAMETER Type
The NT type.
.PARAMETER Read
Shown only read access.
.PARAMETER Write
Shown only write access.
.PARAMETER Execute
Shown only execute access.
.PARAMETER Mandatory
Shown only default mandatory access.
.INPUTS
None
.OUTPUTS
AccessMask entries.
#>
function Get-NtTypeAccess {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [NtApiDotNet.NtType]$Type,
        [Parameter(ParameterSetName = "Read")]
        [switch]$Read,
        [Parameter(ParameterSetName = "Write")]
        [switch]$Write,
        [Parameter(ParameterSetName = "Execute")]
        [switch]$Execute,
        [Parameter(ParameterSetName = "Mandatory")]
        [switch]$Mandatory
    )

    $access = switch ($PSCmdlet.ParameterSetName) {
        "All" { $Type.AccessRights }
        "Read" { $Type.ReadAccessRights }
        "Write" { $Type.WriteAccessRights }
        "Execute" { $Type.ExecuteAccessRights }
        "Mandatory" { $Type.MandatoryAccessRights }
    }

    $access | Write-Output
}

<#
.SYNOPSIS
Get an ATOM objects.
.DESCRIPTION
This cmdlet gets all ATOM objects or by name or atom.
.PARAMETER Atom
Specify the ATOM to get.
.PARAMETER Name
Specify the name of the ATOM to get.
.INPUTS
None
.OUTPUTS
NtApiDotNet.NtAtom
#>
function Get-NtAtom {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [Parameter(Mandatory, ParameterSetName = "FromAtom")]
        [uint16]$Atom,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromName")]
        [string]$Name
    )

    switch ($PSCmdlet.ParameterSetName) {
        "All" { [NtApiDotNet.NtAtom]::GetAtoms() | Write-Output }
        "FromAtom" { [NtApiDotNet.NtAtom]::Open($Atom) | Write-Output }
        "FromName" { [NtApiDotNet.NtAtom]::Find($Name) | Write-Output }
    }
}

<#
.SYNOPSIS
Add a ATOM object.
.DESCRIPTION
This cmdlet adds an ATOM objects.
.PARAMETER Name
Specify the name of the ATOM to add.
.PARAMETER Flags
Specify the flags for the ATOM.
.INPUTS
None
.OUTPUTS
NtApiDotNet.NtAtom
#>
function Add-NtAtom {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,
        [NtApiDotNet.AddAtomFlags]$Flags = 0
    )

    [NtApiDotNet.NtAtom]::Add($Name, $Flags) | Write-Output
}

<#
.SYNOPSIS
Removes an ATOM object.
.DESCRIPTION
This cmdlet removes an ATOM object by name or atom.
.PARAMETER Object
Specify the NtAtom object to remove.
.PARAMETER Atom
Specify the ATOM to remove.
.PARAMETER Name
Specify the name of the ATOM to remove.
.INPUTS
None
.OUTPUTS
None
#>
function Remove-NtAtom {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromObject")]
        [NtApiDotNet.NtAtom]$Object,
        [Parameter(Mandatory, ParameterSetName = "FromAtom")]
        [uint16]$Atom,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "FromName")]
        [string]$Name
    )

    $obj = switch ($PSCmdlet.ParameterSetName) {
        "FromObject" { $Object }
        "FromAtom" { Get-NtAtom -Atom $Atom }
        "FromName" { Get-NtATom -Name $Name }
    }

    if ($null -ne $obj) {
        $obj.Delete()
    }
}

<#
.SYNOPSIS
Loads a DLL into memory.
.DESCRIPTION
This cmdlet loads a DLL into memory with specified flags.
.PARAMETER Path
Specify the path to the DLL.
.PARAMETER Flags
Specify the flags for loading.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.SafeLoadLibraryHandle
#>
function Import-Win32Module {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Path,
        [Parameter(Position = 1)]
        [NtApiDotNet.Win32.LoadLibraryFlags]$Flags = 0
    )

    [NtApiDotNet.Win32.SafeLoadLibraryHandle]::LoadLibrary($Path, $Flags) | Write-Output
}

<#
.SYNOPSIS
Gets an existing DLL from memory.
.DESCRIPTION
This cmdlet finds an existing DLL from memory.
.PARAMETER Path
Specify the path to the DLL.
.PARAMETER Address
Specify the address of the module.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.SafeLoadLibraryHandle
#>
function Get-Win32Module {
    [CmdletBinding(DefaultParameterSetName = "FromPath")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromPath")]
        [string]$Path,
        [Parameter(Mandatory, ParameterSetName = "FromAddress")]
        [IntPtr]$Address
    )

    if ($PSCmdlet.ParameterSetName -eq "FromPath") {
        [NtApiDotNet.Win32.SafeLoadLibraryHandle]::GetModuleHandle($Path) | Write-Output
    }
    else {
        [NtApiDotNet.Win32.SafeLoadLibraryHandle]::GetModuleHandle($Address) | Write-Output
    }
}

<#
.SYNOPSIS
Gets the exports from a loaded DLL.
.DESCRIPTION
This cmdlet gets the list of exports from a loaded DLL or a single exported function.
.PARAMETER Module
Specify the DLL.
.PARAMETER Path
Specify the path to the DLL.
.PARAMETER ProcAddress
Specify the name of the function to query.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.DllExport[] or int64.
#>
function Get-Win32ModuleExport {
    [CmdletBinding(DefaultParameterSetName = "FromModule")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromModule")]
        [NtApiDotNet.Win32.SafeLoadLibraryHandle]$Module,
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromPath")]
        [string]$Path,
        [string]$ProcAddress = ""
    )

    if ($PsCmdlet.ParameterSetName -eq "FromPath") {
        Use-NtObject($lib = Import-Win32Module -Path $Path -Flags LoadLibraryAsDataFile) {
            if ($null -ne $lib) {
                Get-Win32ModuleExport -Module $lib -ProcAddress $ProcAddress
            }
        }
    }
    else {
        if ($ProcAddress -eq "") {
            $Module.Exports | Write-Output
        }
        else {
            $Module.GetProcAddress($ProcAddress, $true).Result.ToInt64() | Write-Output
        }
    }
}

<#
.SYNOPSIS
Gets the imports from a loaded DLL.
.DESCRIPTION
This cmdlet gets the list of imports from a loaded DLL.
.PARAMETER Module
Specify the DLL.
.PARAMETER Path
Specify the path to the DLL.
.PARAMETER DllName
Specify a name of a DLL to only show imports from.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.DllImport[]
#>
function Get-Win32ModuleImport {
    [CmdletBinding(DefaultParameterSetName = "FromModule")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromModule")]
        [NtApiDotNet.Win32.SafeLoadLibraryHandle]$Module,
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromPath")]
        [string]$Path,
        [string]$DllName
    )

    $imports = if ($PsCmdlet.ParameterSetName -eq "FromPath") {
        Use-NtObject($lib = Import-Win32Module -Path $Path -Flags LoadLibraryAsDataFile) {
            if ($null -ne $lib) {
                Get-Win32ModuleImport -Module $lib
            }
        }
    }
    else {
        $Module.Imports
    }

    if ($DllName -ne "") {
        $imports | Where-Object DllName -eq $DllName | Select-Object -ExpandProperty Functions | Write-Output
    }
    else {
        $imports | Write-Output
    }
}

<#
.SYNOPSIS
Gets entries from an object directory.
.DESCRIPTION
This cmdlet gets the list entries in an object directory.
.PARAMETER Directory
Specify the directory.
.INPUTS
None
.OUTPUTS
NtApiDotNet.ObjectDirectoryInformation[]
.EXAMPLE
Get-NtDirectoryEntry $dir
Get list of entries from $dir.
#>
function Get-NtDirectoryEntry {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.NtDirectory]$Directory
    )

    $Directory.Query() | Write-Output
}

<#
.SYNOPSIS
Get current authentication packages.
.DESCRIPTION
This cmdlet gets the list of current authentication packages.
.PARAMETER Name
The name of the authentication package.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.AuthenticationPackage
.EXAMPLE
Get-AuthPackage
Get all authentication packages.
.EXAMPLE
Get-AuthPackage -Name NTLM
Get the NTLM authentication package.
#>
function Get-AuthPackage {
    [CmdletBinding(DefaultParameterSetName = "All")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromName")]
        [string]$Name
    )

    switch ($PSCmdlet.ParameterSetName) {
        "All" {
            [NtApiDotNet.Win32.Security.Authentication.AuthenticationPackage]::Get() | Write-Output
        }
        "FromName" {
            [NtApiDotNet.Win32.Security.Authentication.AuthenticationPackage]::FromName($Name) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Read's user credentials from the shell.
.DESCRIPTION
This cmdlet reads the user credentials from the shell and encodes the password.
.PARAMETER UserName
The username to use.
.PARAMETER Domain
The domain to use.
.PARAMETER Password
The password to use.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.UserCredentials
.EXAMPLE
$user_creds = Read-UserCredentials
Read user credentials from the shell.
#>
function Read-AuthCredential {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0)]
        [string]$UserName,
        [Parameter(Position = 1)]
        [string]$Domain,
        [Parameter(Position = 2)]
        [string]$Password
    )

    $creds = [NtApiDotNet.Win32.Security.Authentication.UserCredentials]::new()
    if ($UserName -eq "") {
        $UserName = Read-Host -Prompt "UserName"
    }
    $creds.UserName = $UserName
    if ($Domain -eq "") {
        $Domain = Read-Host -Prompt "Domain"
    }
    $creds.Domain = $Domain
    if ($Password -ne "") {
        $creds.SetPassword($Password)
    }
    else {
        $creds.Password = Read-Host -AsSecureString -Prompt "Password"
    }
    $creds | Write-Output
}

<#
.SYNOPSIS
Get user credentials.
.DESCRIPTION
This cmdlet gets user credentials and encodes the password.
.PARAMETER UserName
The username to use.
.PARAMETER Domain
The domain to use.
.PARAMETER Password
The password to use.
.PARAMETER SecurePassword
The secure password to use.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.UserCredentials
.EXAMPLE
$user_creds = Get-UserCredentials -UserName "ABC" -Domain "DOMAIN" -Password "pwd"
Get user credentials from components.
#>
function Get-AuthCredential {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0)]
        [string]$UserName,
        [Parameter(Position = 1)]
        [string]$Domain,
        [Parameter(Position = 2)]
        [string]$Password,
        [Parameter]
        [System.Security.SecureString]$SecurePassword
    )

    $creds = [NtApiDotNet.Win32.Security.Authentication.UserCredentials]::new()
    if ($UserName -NE "") {
        $creds.UserName = $UserName
    }
    
    if ($Domain -NE "") {
        $creds.Domain = $Domain
    }

    if ($Password -NE "") {
        $creds.SetPassword($Password)
    }
    else {
        $creds.Password = $SecurePassword
    }
    $creds | Write-Output
}

<#
.SYNOPSIS
Create a new credentials handle.
.DESCRIPTION
This cmdlet creates a new authentication credentials handle.
.PARAMETER Package
The name of the package to use.
.PARAMETER UseFlag
The use flags for the credentials.
.PARAMETER AuthId
Optional authentication ID to authenticate.
.PARAMETER Principal
Optional principal to authentication.
.PARAMETER Credential
Optional Credentials for the authentication.
.PARAMETER ReadCredential
Specify to read the credentials from the console if not specified explicitly.
.PARAMETER UserName
The username to use.
.PARAMETER Domain
The domain to use.
.PARAMETER Password
The password to use.
.PARAMETER SecurePassword
The secure password to use.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.CredentialHandle
.EXAMPLE
$h = Get-AuthCredentialHandle -Package "NTLM" -UseFlag Both
Get a credential handle for the NTLM package for both directions.
.EXAMPLE
$h = Get-AuthCredentialHandle -Package "NTLM" -UseFlag Both -UserName "user" -Password "pwd"
Get a credential handle for the NTLM package for both directions with a username password.
.EXAMPLE
$h = Get-AuthCredentialHandle -Package "NTLM" -UseFlag Inbound -ReadCredential
Get a credential handle for the NTLM package for outbound directions and read credentials from the shell.
#>
function Get-AuthCredentialHandle {
    [CmdletBinding(DefaultParameterSetName="FromCreds")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Package,
        [Parameter(Position = 1, Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.SecPkgCredFlags]$UseFlag,
        [Nullable[NtApiDotNet.Luid]]$AuthId,
        [string]$Principal,
        [Parameter(ParameterSetName="FromCreds")]
        [NtApiDotNet.Win32.Security.Authentication.AuthenticationCredentials]$Credential,
        [Parameter(ParameterSetName="FromParts")]
        [switch]$ReadCredential,
        [Parameter(ParameterSetName="FromParts")]
        [string]$UserName,
        [Parameter(ParameterSetName="FromParts")]
        [string]$Domain,
        [Parameter(ParameterSetName="FromParts")]
        [string]$Password,
        [Parameter(ParameterSetName="FromParts")]
        [System.Security.SecureString]$SecurePassword
    )

    if ($PSCmdlet.ParameterSetName -EQ "FromParts") {
        if ($ReadCredential) {
            $Credential = Read-AuthCredential -UserName $UserName -Domain $Domain `
                    -Password $Password
        } else {
            $Credential = Get-AuthCredential -UserName $UserName -Domain $Domain `
                    -Password $Password -SecurePassword $SecurePassword
        }
    }

    [NtApiDotNet.Win32.Security.Authentication.CredentialHandle]::Create($Principal, $Package, $AuthId, $UseFlag, $Credential) | Write-Output
}

<#
.SYNOPSIS
Create a new authentication client.
.DESCRIPTION
This cmdlet creates a new authentication client.
.PARAMETER CredHandle
The credential handle to use.
.PARAMETER RequestAttribute
Request attributes.
.PARAMETER Target
Optional SPN target.
.PARAMETER DataRepresentation
Data representation format.
.PARAMETER ChannelBinding
Optional channel binding token.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.ClientAuthenticationContext
#>
function Get-AuthClientContext {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.CredentialHandle]$CredHandle,
        [NtApiDotNet.Win32.Security.Authentication.InitializeContextReqFlags]$RequestAttribute = 0,
        [string]$Target,
        [byte[]]$ChannelBinding,
        [NtApiDotNet.Win32.Security.Authentication.SecDataRep]$DataRepresentation = "Native"
    )

    [NtApiDotNet.Win32.Security.Authentication.ClientAuthenticationContext]::new($CredHandle, `
            $RequestAttribute, $Target, $ChannelBinding, $DataRepresentation) | Write-Output
}

<#
.SYNOPSIS
Create a new authentication server.
.DESCRIPTION
This cmdlet creates a new authentication server.
.PARAMETER CredHandle
The credential handle to use.
.PARAMETER RequestAttribute
Request attributes.
.PARAMETER DataRepresentation
Data representation format.
.PARAMETER ChannelBinding
Optional channel binding token.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.ServerAuthenticationContext
#>
function Get-AuthServerContext {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.CredentialHandle]$CredHandle,
        [NtApiDotNet.Win32.Security.Authentication.AcceptContextReqFlags]$RequestAttribute = 0,
        [NtApiDotNet.Win32.Security.Authentication.SecDataRep]$DataRepresentation = "Native",
        [byte[]]$ChannelBinding
    )

    [NtApiDotNet.Win32.Security.Authentication.ServerAuthenticationContext]::new($CredHandle, `
            $RequestAttribute, $ChannelBinding, $DataRepresentation) | Write-Output
}

<#
.SYNOPSIS
Update an authentication client.
.DESCRIPTION
This cmdlet updates an authentication client. Returns true if the authentication is complete.
.PARAMETER Server
The authentication client.
.PARAMETER Token
The next authentication token.
.INPUTS
None
.OUTPUTS
bool
#>
function Update-AuthClientContext {
    [CmdletBinding(DefaultParameterSetName="FromToken")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.ClientAuthenticationContext]$Client,
        [Parameter(Position = 1, Mandatory, ParameterSetName="FromToken")]
        [NtApiDotNet.Win32.Security.Authentication.AuthenticationToken]$Token,
        [Parameter(Position = 1, Mandatory, ParameterSetName="FromContext")]
        [NtApiDotNet.Win32.Security.Authentication.ServerAuthenticationContext]$Server
    )

    if ($PSCmdlet.ParameterSetName -eq "FromContext") {
        $Token = $Server.Token
    }
    $Client.Continue($Token)
}

<#
.SYNOPSIS
Update an authentication server.
.DESCRIPTION
This cmdlet updates an authentication server. Returns true if the authentication is complete.
.PARAMETER Server
The authentication server.
.PARAMETER Client
The authentication client to extract token from.
.PARAMETER Token
The next authentication token.
.INPUTS
None
.OUTPUTS
bool
#>
function Update-AuthServerContext {
    [CmdletBinding(DefaultParameterSetName="FromToken")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.ServerAuthenticationContext]$Server,
        [Parameter(Position = 1, Mandatory, ParameterSetName="FromContext")]
        [NtApiDotNet.Win32.Security.Authentication.ClientAuthenticationContext]$Client,
        [Parameter(Position = 1, Mandatory, ParameterSetName="FromToken")]
        [NtApiDotNet.Win32.Security.Authentication.AuthenticationToken]$Token
    )

    if ($PSCmdlet.ParameterSetName -eq "FromContext") {
        $Token = $Client.Token
    }

    $Server.Continue($Token)
}

<#
.SYNOPSIS
Get access token for the authentication.
.DESCRIPTION
This cmdlet gets the access token for authentication, once complete.
.PARAMETER Server
The authentication server.
.INPUTS
None
.OUTPUTS
NtApiDotNet.NtToken
#>
function Get-AuthAccessToken {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.ServerAuthenticationContext]$Server
    )

    $Server.GetAccessToken() | Write-Output
}

<#
.SYNOPSIS
Gets an authentication token.
.DESCRIPTION
This cmdlet gets an authentication token from a context or from 
an array of bytes.
.PARAMETER Context
The authentication context to extract token from.
.PARAMETER Token
The array of bytes for the new token.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.AuthenticationToken
#>
function Get-AuthToken {
    [CmdletBinding(DefaultParameterSetName="FromContext")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromBytes")]
        [byte[]]$Token,
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromContext")]
        [NtApiDotNet.Win32.Security.Authentication.IAuthenticationContext]$Context
    )

    PROCESS {
        if ($PSCmdlet.ParameterSetName -eq "FromContext") {
            $Context.Token | Write-Output
        } else {
            [NtApiDotNet.Win32.Security.Authentication.AuthenticationToken]::Parse($Token)
        }
    }
}

<#
.SYNOPSIS
Tests an authentication context to determine if it's complete.
.DESCRIPTION
This cmdlet tests and authentication context to determine if it's complete.
.PARAMETER Context
The authentication context to test.
.INPUTS
None
.OUTPUTS
bool
#>
function Test-AuthContext {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.IAuthenticationContext]$Context
    )

    return $Context.Done
}

<#
.SYNOPSIS
Format an authentication token.
.DESCRIPTION
This cmdlet formats an authentication token. Defaults to
a hex dump if format unknown.
.PARAMETER Context
The authentication context to extract token from.
.PARAMETER Token
The authentication token to format.
.PARAMETER AsBytes
Always format as a hex dump.
.PARAMETER AsDER
Always format as a ASN.1 DER structure.
.INPUTS
None
.OUTPUTS
string
#>
function Format-AuthToken {
    [CmdletBinding(DefaultParameterSetName="FromContext")]
    Param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ParameterSetName="FromToken")]
        [NtApiDotNet.Win32.Security.Authentication.AuthenticationToken]$Token,
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromContext")]
        [NtApiDotNet.Win32.Security.Authentication.IAuthenticationContext]$Context,
        [switch]$AsBytes,
        [switch]$AsDER
    )

    PROCESS {
        if ($PSCmdlet.ParameterSetName -eq "FromContext") {
            $Token = $Context.Token
        }
        if ($AsBytes) {
            $ba = $Token.ToArray()
            if ($ba.Length -gt 0) {
                Out-HexDump -Bytes $ba -ShowAll
            }
        } elseif ($AsDER) {
            $ba = $Token.ToArray()
            if ($ba.Length -gt 0) {
                Format-ASN1DER -Bytes $ba
            }
        } else {
            $Token.Format() | Write-Output
        }
    }
}

<#
.SYNOPSIS
Exports an authentication token to a file.
.DESCRIPTION
This cmdlet exports an authentication token to a file.
.PARAMETER Context
The authentication context to extract token from.
.PARAMETER Token
The authentication token to export.
.PARAMETER Path
The path to the file to export.
.INPUTS
None
.OUTPUTS
None
#>
function Export-AuthToken {
    [CmdletBinding(DefaultParameterSetName="FromContext")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromToken")]
        [NtApiDotNet.Win32.Security.Authentication.AuthenticationToken]$Token,
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromContext")]
        [NtApiDotNet.Win32.Security.Authentication.IAuthenticationContext]$Context,
        [Parameter(Position = 1, Mandatory)]
        [string]$Path
    )

    if ($PSCmdlet.ParameterSetName -eq "FromContext") {
        $Token = $Context.Token
    }

    $Token.ToArray() | Set-Content -Path $Path -Encoding Byte
}

<#
.SYNOPSIS
Imports an authentication token to a file.
.DESCRIPTION
This cmdlet imports an authentication token from a file.
.PARAMETER Path
The path to the file to import.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.AuthenticationToken
#>
function Import-AuthToken {
    [CmdletBinding(DefaultParameterSetName="FromContext")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Path
    )

    $token = [NtApiDotNet.Win32.Security.Authentication.AuthenticationToken][byte[]](Get-Content -Path $Path -Encoding Byte)
    Write-Output $token
}

<#
.SYNOPSIS
Get list of loaded kernel modules.
.DESCRIPTION
This cmdlet gets the list of loaded kernel modules.
.INPUTS
None
.OUTPUTS
NtApiDotNet.ProcessModule[]
#>
function Get-NtKernelModule {
    [NtApiDotNet.NtSystemInfo]::GetKernelModules() | Write-Output
}

<#
.SYNOPSIS
Gets the information classes for a type.
.DESCRIPTION
This cmdlet gets the list of information classes for a type. You can get the query and set information classes.
.PARAMETER Type
The NT type to get information classes for.
.PARAMETER Object
The object to get information classes for.
.PARAMETER Set
Specify to get the set information classes which might differ.
.INPUTS
None
.OUTPUTS
KeyPair<string, int>[]
#>
function Get-NtObjectInformationClass {
    [CmdletBinding(DefaultParameterSetName = "FromType")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromType")]
        [NtApiDotNet.NtType]$Type,
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromObject")]
        [NtApiDotNet.NtObject]$Object,
        [switch]$Set
    )

    if ($PSCmdlet.ParameterSetName -eq "FromObject") {
        $Type = $Object.NtType
    }

    if ($Set) {
        $Type.SetInformationClass | Write-Output
    }
    else {
        $Type.QueryInformationClass | Write-Output
    }
}

<#
.SYNOPSIS
Compares two object handles to see if they're the same underlying object.
.DESCRIPTION
This cmdlet compares two handles to see if they're the same underlying object.
On Window 10 this is a supported operation, for downlevel queries the address for
the objects and compares that instead.
.PARAMETER Left
The left hand object to compare.
.PARAMETER Right
The right hand object to compare.
.INPUTS
None
.OUTPUTS
bool
#>
function Compare-NtObject {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.NtObject]$Left,
        [Parameter(Position = 1, Mandatory)]
        [NtApiDotNet.NtObject]$Right
    )
    $Left.SameObject($Right) | Write-Output
}

<#
.SYNOPSIS
Copies a security descriptor to a new one.
.DESCRIPTION
This cmdlet copies the details from a security descriptor into a new object so
that it can be modified without affecting the other.
.PARAMETER SecurityDescriptor
The security descriptor to copy.
.INPUTS
None
.OUTPUTS
NtApiDotNet.SecurityDescriptor
#>
function Copy-NtSecurityDescriptor {
    Param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor
    )
    $SecurityDescriptor.Clone() | Write-Output
}

<#
.SYNOPSIS
Edits an existing security descriptor.
.DESCRIPTION
This cmdlet edits an existing security descriptor in-place. This can be based on
a new security descriptor and additional information. If PassThru is specified
the the SD is not editing in place, a clone of the SD will be returned.
.PARAMETER SecurityDescriptor
The security descriptor to edit.
.PARAMETER NewSecurityDescriptor
The security to update with.
.PARAMETER SecurityInformation
Specify the parts of the security descriptor to edit.
.PARAMETER Token
Specify optional token used to edit the security descriptor.
.PARAMETER Flags
Specify optional auto inherit flags.
.PARAMETER Type
Specify the NT type to use for the update. Defaults to using the
type from $SecurityDescriptor.
.PARAMETER MapGeneric
Map generic access rights to specific access rights.
.PARAMETER PassThru
Passthrough the security descriptor.
.INPUTS
None
.OUTPUTS
NtApiDotNet.SecurityDescriptor
.EXAMPLE
Edit-NtSecurityDescriptor $sd -CanonicalizeDacl
Canonicalize the security descriptor's DACL.
.EXAMPLE
Edit-NtSecurityDescriptor $sd -MapGenericAccess
Map the security descriptor's generic access to type specific access.
.EXAMPLE
Copy-NtSecurityDescriptor $sd | Edit-NtSecurityDescriptor -MapGenericAccess -PassThru
Make a copy of a security descriptor and edit the copy.
#>
function Edit-NtSecurityDescriptor {
    Param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, Mandatory, ParameterSetName = "ModifySd")]
        [NtApiDotNet.SecurityDescriptor]$NewSecurityDescriptor,
        [Parameter(Position = 2, Mandatory, ParameterSetName = "ModifySd")]
        [NtApiDotNet.SecurityInformation]$SecurityInformation,
        [Parameter(ParameterSetName = "ModifySd")]
        [NtApiDotNet.NtToken]$Token,
        [Parameter(ParameterSetName = "ModifySd")]
        [NtApiDotNet.SecurityAutoInheritFlags]$Flags = 0,
        [Parameter(ParameterSetName = "ModifySd")]
        [Parameter(ParameterSetName = "ToAutoInherit")]
        [Parameter(ParameterSetName = "MapGenericSd")]
        [NtApiDotNet.NtType]$Type,
        [Parameter(ParameterSetName = "CanonicalizeSd")]
        [switch]$CanonicalizeDacl,
        [Parameter(ParameterSetName = "CanonicalizeSd")]
        [switch]$CanonicalizeSacl,
        [Parameter(Mandatory, ParameterSetName = "MapGenericSd")]
        [switch]$MapGeneric,
        [Parameter(Mandatory, ParameterSetName = "ToAutoInherit")]
        [switch]$ConvertToAutoInherit,
        [Parameter(ParameterSetName = "ToAutoInherit")]
        [switch]$Container,
        [Parameter(ParameterSetName = "ToAutoInherit")]
        [NtApiDotNet.SecurityDescriptor]$Parent,
        [Nullable[Guid]]$ObjectType = $null,
        [switch]$PassThru
    )

    if ($PassThru) {
        $SecurityDescriptor = Copy-NtSecurityDescriptor $SecurityDescriptor
    }

    if ($PSCmdlet.ParameterSetName -ne "CanonicalizeSd") {
        if ($null -eq $Type) {
            $Type = $SecurityDescriptor.NtType
            if ($null -eq $Type) {
                Write-Warning "Original type not available, defaulting to File."
                $Type = Get-NtType "File"
            }
        }
    }

    if ($PsCmdlet.ParameterSetName -eq "ModifySd") {
        $SecurityDescriptor.Modify($NewSecurityDescriptor, $SecurityInformation, `
                $Flags, $Token, $Type.GenericMapping)
    }
    elseif ($PsCmdlet.ParameterSetName -eq "CanonicalizeSd") {
        if ($CanonicalizeDacl) {
            $SecurityDescriptor.CanonicalizeDacl()
        }
        if ($CanonicalizeSacl) {
            $SecurityDescriptor.CanonicalizeSacl()
        }
    }
    elseif ($PsCmdlet.ParameterSetName -eq "MapGenericSd") {
        $SecurityDescriptor.MapGenericAccess($Type)
    }
    elseif ($PsCmdlet.ParameterSetName -eq "ToAutoInherit") {
        $SecurityDescriptor.ConvertToAutoInherit($Parent,
            $ObjectType, $Container, $Type.GenericMapping)
    }

    if ($PassThru) {
        $SecurityDescriptor | Write-Output
    }
}

<#
.SYNOPSIS
Sets the owner for a security descriptor.
.DESCRIPTION
This cmdlet sets the owner of a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.PARAMETER Owner
The owner SID to set.
.PARAMETER Name
The name of the group to set.
.PARAMETER KnownSid
The well known SID to set.
.PARAMETER Defaulted
Specify whether the owner is defaulted.
.PARAMETER
.INPUTS
None
.OUTPUTS
None
#>
function Set-NtSecurityDescriptorOwner {
    [CmdletBinding(DefaultParameterSetName = "FromSid")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, Mandatory, ParameterSetName = "FromSid")]
        [NtApiDotNet.Sid]$Owner,
        [Parameter(Mandatory, ParameterSetName = "FromName")]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName = "FromKnownSid")]
        [NtApiDotNet.KnownSidValue]$KnownSid,
        [switch]$Defaulted
    )

    $sid = switch ($PsCmdlet.ParameterSetName) {
        "FromSid" {
            $Owner
        }
        "FromName" {
            Get-NtSid -Name $Name
        }
        "FromKnownSid" {
            Get-NtSid -KnownSid $KnownSid
        }
    }

    $SecurityDescriptor.Owner = [NtApiDotNet.SecurityDescriptorSid]::new($sid, $Defaulted)
}

<#
.SYNOPSIS
Test various properties of the security descriptor..
.DESCRIPTION
This cmdlet tests various properties of the security descriptor. The default is
to check if the DACL is present.
.PARAMETER SecurityDescriptor
The security descriptor to test.
.PARAMETER DaclPresent
Test if the DACL is present.
.PARAMETER SaclPresent
Test if the SACL is present.
.PARAMETER DaclCanonical
Test if the DACL is canonical.
.PARAMETER SaclCanonical
Test if the SACL is canonical.
.PARAMETER DaclDefaulted
Test if the DACL is defaulted.
.PARAMETER DaclAutoInherited
Test if the DACL is auto-inherited.
.PARAMETER SaclDefaulted
Test if the DACL is defaulted.
.PARAMETER SaclAutoInherited
Test if the DACL is auto-inherited.
.INPUTS
None
.OUTPUTS
Boolean or PSObject.
#>
function Test-NtSecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName = "DaclPresent")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(ParameterSetName = "DaclPresent")]
        [switch]$DaclPresent,
        [Parameter(Mandatory, ParameterSetName = "SaclPresent")]
        [switch]$SaclPresent,
        [Parameter(Mandatory, ParameterSetName = "DaclCanonical")]
        [switch]$DaclCanonical,
        [Parameter(Mandatory, ParameterSetName = "SaclCanonical")]
        [switch]$SaclCanonical,
        [Parameter(Mandatory, ParameterSetName = "DaclDefaulted")]
        [switch]$DaclDefaulted,
        [Parameter(Mandatory, ParameterSetName = "DaclAutoInherited")]
        [switch]$DaclAutoInherited,
        [Parameter(Mandatory, ParameterSetName = "SaclDefaulted")]
        [switch]$SaclDefaulted,
        [Parameter(Mandatory, ParameterSetName = "SaclAutoInherited")]
        [switch]$SaclAutoInherited,
        [Parameter(ParameterSetName = "DaclNull")]
        [switch]$DaclNull,
        [Parameter(Mandatory, ParameterSetName = "SaclNull")]
        [switch]$SaclNull
    )

    $obj = switch ($PSCmdlet.ParameterSetName) {
        "DaclPresent" { $SecurityDescriptor.DaclPresent }
        "SaclPresent" { $SecurityDescriptor.SaclPresent }
        "DaclCanonical" { $SecurityDescriptor.DaclCanonical }
        "SaclCanonical" { $SecurityDescriptor.SaclCanonical }
        "DaclDefaulted" { $SecurityDescriptor.DaclDefaulted }
        "SaclDefaulted" { $SecurityDescriptor.SaclDefaulted }
        "DaclAutoInherited" { $SecurityDescriptor.DaclAutoInherited }
        "SaclAutoInherited" { $SecurityDescriptor.SaclAutoInherited }
        "DaclNull" { $SecurityDescriptor.DaclNull }
        "SaclNull" { $SecurityDescriptor.SaclNull }
    }
    Write-Output $obj
}

<#
.SYNOPSIS
Get the owner from a security descriptor.
.DESCRIPTION
This cmdlet gets the Owner field from a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to query.
.INPUTS
None
.OUTPUTS
NtApiDotNet.SecurityDescriptorSid
#>
function Get-NtSecurityDescriptorOwner {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor
    )
    $SecurityDescriptor.Owner | Write-Output
}

<#
.SYNOPSIS
Get the group from a security descriptor.
.DESCRIPTION
This cmdlet gets the Group field from a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to query.
.INPUTS
None
.OUTPUTS
NtApiDotNet.SecurityDescriptorSid
#>
function Get-NtSecurityDescriptorGroup {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor
    )
    $SecurityDescriptor.Group | Write-Output
}

<#
.SYNOPSIS
Get the DACL from a security descriptor.
.DESCRIPTION
This cmdlet gets the Dacl field from a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to query.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Acl
#>
function Get-NtSecurityDescriptorDacl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor
    )
    Write-Output $SecurityDescriptor.Dacl -NoEnumerate
}

<#
.SYNOPSIS
Get the SACL from a security descriptor.
.DESCRIPTION
This cmdlet gets the Sacl field from a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to query.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Acl
#>
function Get-NtSecurityDescriptorSacl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor
    )
    Write-Output $SecurityDescriptor.Sacl -NoEnumerate
}

<#
.SYNOPSIS
Get the Control from a security descriptor.
.DESCRIPTION
This cmdlet gets the Control field from a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to query.
.INPUTS
None
.OUTPUTS
NtApiDotNet.SecurityDescriptorControl
#>
function Get-NtSecurityDescriptorControl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor
    )
    Write-Output $SecurityDescriptor.Control
}

<#
.SYNOPSIS
Get the Integrity Level from a security descriptor.
.DESCRIPTION
This cmdlet gets the Integrity Level field from a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to query.
.PARAMETER Sid
Get the Integrity Level as a SID.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Sid or NtApiDotNet.TokenIntegrityLevel
#>
function Get-NtSecurityDescriptorIntegrityLevel {
    [CmdletBinding(DefaultParameterSetName = "ToIL")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(ParameterSetName = "ToSid")]
        [switch]$AsSid,
        [Parameter(ParameterSetName = "ToAce")]
        [switch]$AsAce
    )

    if (!$SecurityDescriptor.HasMandatoryLabelAce) {
        return
    }

    switch ($PSCmdlet.ParameterSetName) {
        "ToIL" {
            $SecurityDescriptor.IntegrityLevel
        }
        "ToSid" {
            $SecurityDescriptor.MandatoryLabel.Sid
        }
        "ToAce" {
            $SecurityDescriptor.MandatoryLabel
        }
    }
}

<#
.SYNOPSIS
Sets Control flags for a security descriptor.
.DESCRIPTION
This cmdlet sets Control flags for a security descriptor. Note that you can't
remove the DaclPresent or SaclPresent. For that use Remove-NtSecurityDescriptorDacl
or Remove-NtSecurityDescriptorSacl.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.PARAMETER Control
The control flags to set.
.PARAMETER PassThru
Pass through the final control flags.
.INPUTS
None
.OUTPUTS
None
#>
function Set-NtSecurityDescriptorControl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, Mandatory)]
        [NtApiDotNet.SecurityDescriptorControl]$Control,
        [switch]$PassThru
    )
    $SecurityDescriptor.Control = $Control
    if ($PassThru) {
        $SecurityDescriptor.Control | Write-Output
    }
}

<#
.SYNOPSIS
Adds Control flags for a security descriptor.
.DESCRIPTION
This cmdlet adds Control flags for a security descriptor. Note that you can't
remove the DaclPresent or SaclPresent. For that use Remove-NtSecurityDescriptorDacl
or Remove-NtSecurityDescriptorSacl.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.PARAMETER Control
The control flags to add.
.PARAMETER PassThru
Pass through the final control flags.
.INPUTS
None
.OUTPUTS
None
#>
function Add-NtSecurityDescriptorControl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, Mandatory)]
        [NtApiDotNet.SecurityDescriptorControl]$Control,
        [switch]$PassThru
    )

    $curr_flags = $SecurityDescriptor.Control
    $new_flags = [int]$curr_flags -bor $Control
    $SecurityDescriptor.Control = $new_flags
    if ($PassThru) {
        $SecurityDescriptor.Control | Write-Output
    }
}

<#
.SYNOPSIS
Removes Control flags for a security descriptor.
.DESCRIPTION
This cmdlet removes Control flags for a security descriptor. Note that you can't
remove the DaclPresent or SaclPresent. For that use Remove-NtSecurityDescriptorDacl
or Remove-NtSecurityDescriptorSacl.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.PARAMETER Control
The control flags to remove.
.PARAMETER PassThru
Pass through the final control flags.
.INPUTS
None
.OUTPUTS
None
#>
function Remove-NtSecurityDescriptorControl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, Mandatory)]
        [NtApiDotNet.SecurityDescriptorControl]$Control,
        [switch]$PassThru
    )

    $curr_flags = $SecurityDescriptor.Control
    $new_flags = [int]$curr_flags -band -bnot $Control
    $SecurityDescriptor.Control = $new_flags
    if ($PassThru) {
        $SecurityDescriptor.Control | Write-Output
    }
}

<#
.SYNOPSIS
Creates a new ACL object.
.DESCRIPTION
This cmdlet creates a new ACL object.
.PARAMETER Ace
List of ACEs to create the ACL from.
.PARAMETER Defaulted
Specify whether the ACL is defaulted.
.PARAMETER NullAcl
Specify whether the ACL is NULL.
.PARAMETER AutoInheritReq
Specify to set the Auto Inherit Requested flag.
.PARAMETER AutoInherited
Specify to set the Auto Inherited flag.
.PARAMETER Protected
Specify to set the Protected flag.
.PARAMETER Defaulted
Specify to set the Defaulted flag.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Acl
#>
function New-NtAcl {
    [CmdletBinding(DefaultParameterSetName = "FromAce")]
    Param(
        [Parameter(Mandatory, ParameterSetName = "NullAcl")]
        [switch]$NullAcl,
        [Parameter(ParameterSetName = "FromAce")]
        [NtApiDotNet.Ace[]]$Ace,
        [switch]$AutoInheritReq,
        [switch]$AutoInherited,
        [switch]$Protected,
        [switch]$Defaulted
    )

    $acl = New-Object NtApiDotNet.Acl
    $acl.AutoInherited = $AutoInherited
    $acl.AutoInheritReq = $AutoInheritReq
    $acl.Protected = $Protected
    $acl.Defaulted = $Defaulted
    switch ($PsCmdlet.ParameterSetName) {
        "FromAce" {
            if ($null -ne $Ace) {
                $acl.AddRange($Ace)
            }
        }
        "NullAcl" {
            $acl.NullAcl = $true
        }
    }

    Write-Output $acl -NoEnumerate
}

<#
.SYNOPSIS
Sets the DACL for a security descriptor.
.DESCRIPTION
This cmdlet sets the DACL of a security descriptor. It'll replace any existing DACL assigned.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.PARAMETER Ace
List of ACEs to create the ACL from.
.PARAMETER Defaulted
Specify whether the ACL is defaulted.
.PARAMETER NullAcl
Specify whether the ACL is NULL.
.PARAMETER AutoInheritReq
Specify to set the Auto Inherit Requested flag.
.PARAMETER AutoInherited
Specify to set the Auto Inherited flag.
.PARAMETER Protected
Specify to set the Protected flag.
.PARAMETER Defaulted
Specify to set the Defaulted flag.
.PARAMETER PassThru
Specify to return the new ACL.
.PARAMETER Remove
Specify to remove the ACL.
.INPUTS
None
.OUTPUTS
None
#>
function Set-NtSecurityDescriptorDacl {
    [CmdletBinding(DefaultParameterSetName = "FromAce")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Mandatory, ParameterSetName = "NullAcl")]
        [switch]$NullAcl,
        [Parameter(ParameterSetName = "FromAce")]
        [NtApiDotNet.Ace[]]$Ace,
        [Parameter(ParameterSetName = "NullAcl")]
        [Parameter(ParameterSetName = "FromAce")]
        [switch]$AutoInheritReq,
        [Parameter(ParameterSetName = "NullAcl")]
        [Parameter(ParameterSetName = "FromAce")]
        [switch]$AutoInherited,
        [Parameter(ParameterSetName = "NullAcl")]
        [Parameter(ParameterSetName = "FromAce")]
        [switch]$Protected,
        [Parameter(ParameterSetName = "NullAcl")]
        [Parameter(ParameterSetName = "FromAce")]
        [switch]$Defaulted,
        [Parameter(ParameterSetName = "NullAcl")]
        [Parameter(ParameterSetName = "FromAce")]
        [switch]$PassThru
    )

    $args = @{
        AutoInheritReq = $AutoInheritReq
        AutoInherited  = $AutoInherited
        Protected      = $Protected
        Defaulted      = $Defaulted
    }

    $SecurityDescriptor.Dacl = if ($PSCmdlet.ParameterSetName -eq "NullAcl") {
        New-NtAcl @args -NullAcl
    }
    else {
        New-NtAcl @args -Ace $Ace
    }

    if ($PassThru) {
        Write-Output $SecurityDescriptor.Dacl -NoEnumerate
    }
}

<#
.SYNOPSIS
Sets the SACL for a security descriptor.
.DESCRIPTION
This cmdlet sets the SACL of a security descriptor. It'll replace any existing SACL assigned.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.PARAMETER Ace
List of ACEs to create the ACL from.
.PARAMETER Defaulted
Specify whether the ACL is defaulted.
.PARAMETER NullAcl
Specify whether the ACL is NULL.
.PARAMETER AutoInheritReq
Specify to set the Auto Inherit Requested flag.
.PARAMETER AutoInherited
Specify to set the Auto Inherited flag.
.PARAMETER Protected
Specify to set the Protected flag.
.PARAMETER Defaulted
Specify to set the Defaulted flag.
.PARAMETER PassThru
Specify to return the new ACL.
.PARAMETER Remove
Specify to remove the ACL.
.PARAMETER
.INPUTS
None
.OUTPUTS
None
#>
function Set-NtSecurityDescriptorSacl {
    [CmdletBinding(DefaultParameterSetName = "FromAce")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Mandatory, ParameterSetName = "NullAcl")]
        [switch]$NullAcl,
        [Parameter(ParameterSetName = "FromAce")]
        [NtApiDotNet.Ace[]]$Ace,
        [Parameter(ParameterSetName = "NullAcl")]
        [Parameter(ParameterSetName = "FromAce")]
        [switch]$AutoInheritReq,
        [Parameter(ParameterSetName = "NullAcl")]
        [Parameter(ParameterSetName = "FromAce")]
        [switch]$AutoInherited,
        [Parameter(ParameterSetName = "NullAcl")]
        [Parameter(ParameterSetName = "FromAce")]
        [switch]$Protected,
        [Parameter(ParameterSetName = "NullAcl")]
        [Parameter(ParameterSetName = "FromAce")]
        [switch]$Defaulted,
        [Parameter(ParameterSetName = "NullAcl")]
        [Parameter(ParameterSetName = "FromAce")]
        [switch]$PassThru
    )

    $args = @{
        AutoInheritReq = $AutoInheritReq
        AutoInherited  = $AutoInherited
        Protected      = $Protected
        Defaulted      = $Defaulted
    }

    $SecurityDescriptor.Sacl = if ($PSCmdlet.ParameterSetName -eq "NullAcl") {
        New-NtAcl @args -NullAcl
    }
    else {
        New-NtAcl @args -Ace $Ace
    }
    if ($PassThru) {
        Write-Output $SecurityDescriptor.Sacl -NoEnumerate
    }
}

<#
.SYNOPSIS
Removes the DACL for a security descriptor.
.DESCRIPTION
This cmdlet removes the DACL of a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.INPUTS
None
.OUTPUTS
None
#>
function Remove-NtSecurityDescriptorDacl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor
    )
    $SecurityDescriptor.Dacl = $null
}

<#
.SYNOPSIS
Removes the SACL for a security descriptor.
.DESCRIPTION
This cmdlet removes the SACL of a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.INPUTS
None
.OUTPUTS
None
#>
function Remove-NtSecurityDescriptorSacl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor
    )
    $SecurityDescriptor.Sacl = $null
}

<#
.SYNOPSIS
Clears the DACL for a security descriptor.
.DESCRIPTION
This cmdlet clears the DACL of a security descriptor and unsets NullAcl. If no DACL
is present then nothing modification is performed.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.INPUTS
None
.OUTPUTS
None
#>
function Clear-NtSecurityDescriptorDacl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor
    )

    if ($SecurityDescriptor.DaclPresent) {
        $SecurityDescriptor.Dacl.Clear()
        $SecurityDescriptor.Dacl.NullAcl = $false
    }
}

<#
.SYNOPSIS
Clears the SACL for a security descriptor.
.DESCRIPTION
This cmdlet clears the SACL of a security descriptor and unsets NullAcl. If no SACL
is present then nothing modification is performed.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.INPUTS
None
.OUTPUTS
None
#>
function Clear-NtSecurityDescriptorSacl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor
    )
    if ($SecurityDescriptor.SaclPresent) {
        $SecurityDescriptor.Sacl.Clear()
        $SecurityDescriptor.Sacl.NullAcl = $false
    }
}

<#
.SYNOPSIS
Removes the owner for a security descriptor.
.DESCRIPTION
This cmdlet removes the owner of a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.INPUTS
None
.OUTPUTS
None
#>
function Remove-NtSecurityDescriptorOwner {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor
    )
    $SecurityDescriptor.Owner = $null
}

<#
.SYNOPSIS
Sets the group for a security descriptor.
.DESCRIPTION
This cmdlet sets the group of a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.PARAMETER Group
The group SID to set.
.PARAMETER Name
The name of the group to set.
.PARAMETER KnownSid
The well known SID to set.
.PARAMETER Defaulted
Specify whether the group is defaulted.
.INPUTS
None
.OUTPUTS
None
#>
function Set-NtSecurityDescriptorGroup {
    [CmdletBinding(DefaultParameterSetName = "FromSid")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, Mandatory, ParameterSetName = "FromSid")]
        [NtApiDotNet.Sid]$Group,
        [Parameter(Mandatory, ParameterSetName = "FromName")]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName = "FromKnownSid")]
        [NtApiDotNet.KnownSidValue]$KnownSid,
        [switch]$Defaulted
    )

    $sid = switch ($PsCmdlet.ParameterSetName) {
        "FromSid" {
            $Group
        }
        "FromName" {
            Get-NtSid -Name $Name
        }
        "FromKnownSid" {
            Get-NtSid -KnownSid $KnownSid
        }
    }

    $SecurityDescriptor.Group = [NtApiDotNet.SecurityDescriptorSid]::new($sid, $Defaulted)
}

<#
.SYNOPSIS
Removes the group for a security descriptor.
.DESCRIPTION
This cmdlet removes the group of a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.INPUTS
None
.OUTPUTS
None
#>
function Remove-NtSecurityDescriptorGroup {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor
    )
    $SecurityDescriptor.Group = $null
}

<#
.SYNOPSIS
Removes the integrity level for a security descriptor.
.DESCRIPTION
This cmdlet removes the integrity level of a security descriptor.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.INPUTS
None
.OUTPUTS
None
#>
function Remove-NtSecurityDescriptorIntegrityLevel {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor
    )
    $SecurityDescriptor.RemoveMandatoryLabel()
}

<#
.SYNOPSIS
Sets the integrity level for a security descriptor.
.DESCRIPTION
This cmdlet sets the integrity level for a security descriptor with a specified policy and flags.
.PARAMETER SecurityDescriptor
The security descriptor to modify.
.PARAMETER IntegrityLevel
Specify the integrity level.
.PARAMETER Sid
Specify the integrity level as a SID.
.PARAMETER Flags
Specify the ACE flags.
.PARAMETER Policy
Specify the ACE flags.
.INPUTS
None
.OUTPUTS
None
#>
function Set-NtSecurityDescriptorIntegrityLevel {
    [CmdletBinding(DefaultParameterSetName = "FromLevel")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, Mandatory, ParameterSetName = "FromSid")]
        [NtApiDotNet.Sid]$Sid,
        [Parameter(Position = 1, Mandatory, ParameterSetName = "FromLevel")]
        [NtApiDotNet.TokenIntegrityLevel]$IntegrityLevel,
        [Parameter(ParameterSetName = "FromLevel")]
        [Parameter(ParameterSetName = "FromSid")]
        [NtApiDotNet.AceFlags]$Flags = 0,
        [Parameter(ParameterSetName = "FromLevel")]
        [Parameter(ParameterSetName = "FromSid")]
        [NtApiDotNet.MandatoryLabelPolicy]$Policy = "NoWriteUp"
    )

    switch ($PSCmdlet.ParameterSetName) {
        "FromSid" {
            $SecurityDescriptor.AddMandatoryLabel($Sid, $Flags, $Policy)
        }
        "FromLevel" {
            $SecurityDescriptor.AddMandatoryLabel($IntegrityLevel, $Flags, $Policy)
        }
    }
}

<#
.SYNOPSIS
Converts an ACE condition string expression to a byte array.
.DESCRIPTION
This cmdlet gets a byte array for an ACE conditional string expression.
.PARAMETER Condition
The condition string expression.
.INPUTS
None
.OUTPUTS
byte[]
.EXAMPLE
ConvertFrom-NtAceCondition -Condition 'WIN://TokenId == "TEST"'
Gets the data for the condition expression 'WIN://TokenId == "TEST"'
#>
function ConvertFrom-NtAceCondition {
    [CmdletBinding(DefaultParameterSetName = "FromLevel")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Condition
    )

    [NtApiDotNet.NtSecurity]::StringToConditionalAce($Condition)
}

<#
.SYNOPSIS
Converts an ACE condition byte array to a string.
.DESCRIPTION
This cmdlet converts a byte array for an ACE conditional expression into a string.
.PARAMETER ConditionData
The condition as a byte array.
.INPUTS
None
.OUTPUTS
byte[]
.EXAMPLE
ConvertTo-NtAceCondition -Data $ba
Converts the byte array to a conditional expression string.
#>
function ConvertTo-NtAceCondition {
    [CmdletBinding(DefaultParameterSetName = "FromLevel")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [byte[]]$ConditionData
    )

    [NtApiDotNet.NtSecurity]::ConditionalAceToString($ConditionData)
}

<#
.SYNOPSIS
Converts a security descriptor to a self-relative byte array or base64 string.
.DESCRIPTION
This cmdlet converts a security descriptor to a self-relative byte array or a base64 string.
.PARAMETER SecurityDescriptor
The security descriptor to convert.
.PARAMETER Base64
Converts the self-relative SD to base64 string.
.INPUTS
None
.OUTPUTS
byte[]
.EXAMPLE
ConvertFrom-NtSecurityDescriptor -SecurityDescriptor "O:SYG:SYD:(A;;GA;;;WD)"
Converts security descriptor to byte array.
.EXAMPLE
ConvertFrom-NtSecurityDescriptor -SecurityDescriptor "O:SYG:SYD:(A;;GA;;;WD)" -ToBase64
Converts security descriptor to a base64 string.
.EXAMPLE
ConvertFrom-NtSecurityDescriptor -SecurityDescriptor "O:SYG:SYD:(A;;GA;;;WD)" -ToBase64 -InsertLineBreaks
Converts security descriptor to a base64 string with line breaks.
#>
function ConvertFrom-NtSecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName = "ToBytes")]
    Param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Mandatory, ParameterSetName = "ToBase64")]
        [switch]$Base64,
        [switch]$InsertLineBreaks
    )

    PROCESS {
        if ($Base64) {
            $SecurityDescriptor.ToBase64($InsertLineBreaks) | Write-Output
        }
        else {
            $SecurityDescriptor.ToByteArray() | Write-Output -NoEnumerate
        }
    }
}

<#
.SYNOPSIS
Creates a new UserGroup object from SID and Attributes.
.DESCRIPTION
This cmdlet creates a new UserGroup object from SID and Attributes.
.PARAMETER Sid
List of SIDs to use to create object.
.PARAMETER Attribute
Common attributes for the new object.
.INPUTS
NtApiDotNet.Sid[]
.OUTPUTS
NtApiDotNet.UserGroup[]
.EXAMPLE
New-NtUserGroup -Sid "WD" -Attribute Enabled
Creates a new UserGroup with the World SID and the Enabled Flag.
#>
function New-NtUserGroup {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [NtApiDotNet.Sid[]]$Sid,
        [NtApiDotNet.GroupAttributes]$Attribute = 0
    )

    PROCESS {
        foreach ($s in $Sid) {
            New-Object NtApiDotNet.UserGroup -ArgumentList $s, $Attribute
        }
    }
}

<#
.SYNOPSIS
Formats an object's security descriptor as text.
.DESCRIPTION
This cmdlet formats the security descriptor to text for display in the console or piped to a file
Uses Get-Win32SecurityDescriptor API to query the SD then uses the Format-NtSecurityDescriptor to
display.
.PARAMETER Type
Specify the SE object type for the path. Defaults to File.
.PARAMETER Name
Specify the name of the object for the security descriptor.
.PARAMETER SecurityInformation
Specify what parts of the security descriptor to format.
.PARAMETER Summary
Specify to only print a shortened format removing redundant information.
.PARAMETER ShowAll
Specify to format all security descriptor information including the SACL.
.PARAMETER HideHeader
Specify to not print the security descriptor header.
.PARAMETER ToSddl
Specify to format the security descriptor as SDDL.
.PARAMETER Container
Specify to display the access mask from Container Access Rights.
.OUTPUTS
None
.EXAMPLE
Format-Win32SecurityDescriptor -Name "c:\windows".
Format the security descriptor for the c:\windows folder..
.EXAMPLE
Format-Win32SecurityDescriptor -Name "c:\windows" -ToSddl
Format the security descriptor of an object as SDDL.
.EXAMPLE
Format-Win32SecurityDescriptor -Name "c:\windows" -ToSddl -SecurityInformation Dacl, Label
Format the security descriptor of an object as SDDL with only DACL and Label.
.EXAMPLE
Format-Win32SecurityDescriptor -Name "Machine\Software" -Type RegistryKey
Format the security descriptor of a registry key.
#>
function Format-Win32SecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName = "FromName")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromName", Mandatory)]
        [string]$Name,
        [NtApiDotNet.Win32.Security.Authorization.SeObjectType]$Type = "File",
        [NtApiDotNet.SecurityInformation]$SecurityInformation = "AllBasic",
        [switch]$Container,
        [switch]$ToSddl,
        [switch]$Summary,
        [switch]$ShowAll,
        [switch]$HideHeader
    )

    Get-Win32SecurityDescriptor -Name $Name -SecurityInformation $SecurityInformation `
        -Type $Type | Format-NtSecurityDescriptor -SecurityInformation $SecurityInformation `
        -Container:$Container -ToSddl:$ToSddl -Summary:$Summary -ShowAll:$ShowAll -HideHeader:$HideHeader `
        -DisplayPath $Name
}

<#
.SYNOPSIS
Creates a new Object Type Tree object.
.DESCRIPTION
This cmdlet creates a new Object Type Tree object from a GUID. You can then use Add-ObjectTypeTree to
add more branches to the tree.
.PARAMETER ObjectType
Specify the Object Type GUID.
.PARAMETER Nodes
Specify a list of tree objects to add a children.
.PARAMETER Name
Optional name of the object type.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Utilities.Security.ObjectTypeTree
.EXAMPLE
$tree = New-ObjectTypeTree "bf967a86-0de6-11d0-a285-00aa003049e2"
Creates a new Object Type tree with the root type as 'bf967a86-0de6-11d0-a285-00aa003049e2'.
.EXAMPLE
$tree = New-ObjectTypeTree "bf967a86-0de6-11d0-a285-00aa003049e2" -Nodes $children
Creates a new Object Type tree with the root type as 'bf967a86-0de6-11d0-a285-00aa003049e2' with a list of children.
#>
function New-ObjectTypeTree {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [guid]$ObjectType,
        [NtApiDotNet.Utilities.Security.ObjectTypeTree[]]$Nodes,
        [string]$Name = ""
    )

    $tree = New-Object NtApiDotNet.Utilities.Security.ObjectTypeTree -ArgumentList $ObjectType
    if ($null -ne $Nodes) {
        $tree.AddNodeRange($Nodes)
    }
    $tree.Name = $Name
    Write-Output $tree
}

<#
.SYNOPSIS
Adds a new Object Type Tree node to an existing tree.
.DESCRIPTION
This cmdlet adds a new Object Type Tree object from a GUID to and existing tree.
.PARAMETER ObjectType
Specify the Object Type GUID to add.
.PARAMETER Tree
Specify the root tree to add to.
.PARAMETER Name
Optional name of the object type.
.PARAMETER PassThru
Specify to return the added tree.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Utilities.Security.ObjectTypeTree
.EXAMPLE
Add-ObjectTypeTree $tree "bf967a86-0de6-11d0-a285-00aa003049e2"
Adds a new Object Type tree with the root type as 'bf967a86-0de6-11d0-a285-00aa003049e2'.
.EXAMPLE
Add-ObjectTypeTree $tree "bf967a86-0de6-11d0-a285-00aa003049e2" -Name "Property A"
Adds a new Object Type tree with the root type as 'bf967a86-0de6-11d0-a285-00aa003049e2'.
#>
function Add-ObjectTypeTree {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.Utilities.Security.ObjectTypeTree]$Tree,
        [Parameter(Position = 1, Mandatory)]
        [guid]$ObjectType,
        [string]$Name = "",
        [switch]$PassThru
    )
    $result = $Tree.AddNode($ObjectType)
    $result.Name = $Name
    if ($PassThru) {
        Write-Output $result
    }
}

<#
.SYNOPSIS
Removes an Object Type Tree node.
.DESCRIPTION
This cmdlet removes a tree node.
.PARAMETER Tree
Specify the tree node to remove.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Remove-ObjectTypeTree $tree
Removes the tree node $tree from its parent.
#>
function Remove-ObjectTypeTree {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.Utilities.Security.ObjectTypeTree]$Tree
    )
    $Tree.Remove()
}

<#
.SYNOPSIS
Sets an Object Type Tree's Remaining Access.
.DESCRIPTION
This cmdlet sets a Object Type Tree's remaining access as well as all its children.
.PARAMETER Tree
Specify tree node to set.
.PARAMETER Access
Specify the access to set.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-ObjectTypeTreeAccess $tree 0xFF
Sets the Remaning Access for this tree and all children to 0xFF.
#>
function Set-ObjectTypeTreeAccess {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.Utilities.Security.ObjectTypeTree]$Tree,
        [Parameter(Position = 1, Mandatory)]
        [NtApiDotNet.AccessMask]$Access
    )
    $Tree.SetRemainingAccess($Access)
}

<#
.SYNOPSIS
Revokes an Object Type Tree's Remaining Access.
.DESCRIPTION
This cmdlet revokes a Object Type Tree's remaining access as well as all its children.
.PARAMETER Tree
Specify tree node to revoke.
.PARAMETER Access
Specify the access to revoke.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Revoke-ObjectTypeTreeAccess $tree 0xFF
Revokes the Remaining Access of 0xFF for this tree and all children.
#>
function Revoke-ObjectTypeTreeAccess {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.Utilities.Security.ObjectTypeTree]$Tree,
        [Parameter(Position = 1, Mandatory)]
        [NtApiDotNet.AccessMask]$Access
    )
    $Tree.RemoveRemainingAccess($Access)
}

<#
.SYNOPSIS
Selects out an Object Type Tree node based on the object type.
.DESCRIPTION
This cmdlet selects out an Object Type Tree node based on the object type. Returns $null
if the Object Type can't be found.
.PARAMETER ObjectType
Specify the Object Type GUID to select
.PARAMETER Tree
Specify the tree to check.
.PARAMETER PassThru
Specify to return the added tree.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Utilities.Security.ObjectTypeTree
.EXAMPLE
Select-ObjectTypeTree $tree "bf967a86-0de6-11d0-a285-00aa003049e2"
Selects an Object Type tree with the type of 'bf967a86-0de6-11d0-a285-00aa003049e2'.
#>
function Select-ObjectTypeTree {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.Utilities.Security.ObjectTypeTree]$Tree,
        [Parameter(Position = 1, Mandatory)]
        [guid]$ObjectType
    )
    
    $Tree.Find($ObjectType) | Write-Output
}

<#
.SYNOPSIS
Gets the Central Access Policy from the Registry.
.DESCRIPTION
This cmdlet gets the Central Access Policy from the Registry.
.PARAMETER FromLsa
Parse the Central Access Policy from LSA.
.PARAMETER CapId
Specify the CAPID SID to select.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Security.Policy.CentralAccessPolic
.EXAMPLE
Get-CentralAccessPolicy
Gets the Central Access Policy from the Registry.
.EXAMPLE
Get-CentralAccessPolicy -FromLsa
Gets the Central Access Policy from the LSA.
#>
function Get-CentralAccessPolicy {
    Param(
        [Parameter(Position=0)]
        [NtApiDotNet.Sid]$CapId,
        [switch]$FromLsa
    )
    $policy = if ($FromLsa) {
        [NtApiDotNet.Security.Policy.CentralAccessPolicy]::ParseFromLsa()
    }
    else {
        [NtApiDotNet.Security.Policy.CentralAccessPolicy]::ParseFromRegistry()
    }
    if ($null -eq $CapId) {
        $policy | Write-Output
    } else {
        $policy | Where-Object CapId -eq $CapId | Select-Object -First 1 | Write-Output
    }
}

<#
.SYNOPSIS
Test if an object can be opened.
.DESCRIPTION
This cmdlet tests if an object exists by opening it. This might give false negatives
if the reason for not opening it was unrelated to it not existing.
.PARAMETER Path
Specify an object path to get the security descriptor from.
.PARAMETER TypeName
Specify the type name of the object at Path. Needed if the module cannot automatically determine the NT type to open.
.PARAMETER Root
Specify a root object for Path.
.INPUTS
None
.OUTPUTS
Boolean
.EXAMPLE
Test-NtObject \BaseNamedObjects\ABC
Test if \BaseNamedObjects\ABC can be opened.
.EXAMPLE
Test-NtObject ABC -Root $dir
Test if ABC can be opened relative to $dir.
.EXAMPLE
Test-NtObject \BaseNamedObjects\ABC -TypeName Mutant.
Test if \BaseNamedObjects\ABC can be opened with a File type.
#>
function Test-NtObject {
    [CmdletBinding(DefaultParameterSetName = "FromPath")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromPath")]
        [string]$Path,
        [parameter(ParameterSetName = "FromPath")]
        [string]$TypeName,
        [parameter(ParameterSetName = "FromPath")]
        [NtApiDotNet.NtObject]$Root
    )
    switch ($PsCmdlet.ParameterSetName) {
        "FromPath" {
            try {
                Use-NtObject($obj = Get-NtObject -Path $Path -Root $Root -TypeName $TypeName) { }
                return $true
            } 
            catch {
                return $false
            }
        }
    }
}

<#
.SYNOPSIS
Get the advanced audit policy information.
.DESCRIPTION
This cmdlet gets advanced audit policy information.
.PARAMETER Category
Specify the category type.
.PARAMETER CategoryGuid
Specify the category type GUID.
.PARAMETER ExpandCategory
Specify to expand the subcategories from the category.
.PARAMETER User
Specify the user for a per-user Audit Policies.
.PARAMETER AllUser
Specify to get all users for all per-user Audit Policies.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Audit.AuditCategory
NtApiDotNet.Win32.Security.Audit.AuditSubCategory
NtApiDotNet.Win32.Security.Audit.AuditPerUserCategory
NtApiDotNet.Win32.Security.Audit.AuditPerUserSubCategory
.EXAMPLE
Get-NtAuditPolicy
Get all audit policy categories.
.EXAMPLE
Get-NtAuditPolicy -Category ObjectAccess
Get the ObjectAccess audit policy category
.EXAMPLE
Get-NtAuditPolicy -Category ObjectAccess -Expand
Get the ObjectAccess audit policy category and return the SubCategory policies.
.EXAMPLE
Get-NtAuditPolicy -User $sid
Get all per-user audit policy categories for the user represented by a SID.
.EXAMPLE
Get-NtAuditPolicy -AllUser
Get all per-user audit policy categories for all users.
#>
function Get-NtAuditPolicy {
    [CmdletBinding(DefaultParameterSetName = "All")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromCategory")]
        [NtApiDotNet.Win32.Security.Audit.AuditPolicyEventType[]]$Category,
        [parameter(Mandatory, ParameterSetName = "FromCategoryGuid")]
        [Guid[]]$CategoryGuid,
        [parameter(Mandatory, ParameterSetName = "FromSubCategoryName")]
        [string[]]$SubCategoryName,
        [parameter(Mandatory, ParameterSetName = "FromSubCategoryGuid")]
        [guid[]]$SubCategoryGuid,
        [parameter(ParameterSetName = "All")]
        [parameter(ParameterSetName = "FromCategory")]
        [parameter(ParameterSetName = "FromCategoryGuid")]
        [switch]$ExpandCategory,
        [parameter(ParameterSetName = "All")]
        [switch]$AllUser,
        [NtApiDotNet.Sid]$User
    )

    $cats = switch ($PSCmdlet.ParameterSetName) {
        "All" {
            if ($null -ne $User) {
                [NtApiDotNet.Win32.Security.Audit.AuditSecurityUtils]::GetPerUserCategories($User)
            }
            elseif ($AllUser) {
                [NtApiDotNet.Win32.Security.Audit.AuditSecurityUtils]::GetPerUserCategories()
            }
            else {
                [NtApiDotNet.Win32.Security.Audit.AuditSecurityUtils]::GetCategories()
            }
        }
        "FromCategory" {
            $ret = @()
            foreach($cat in $Category) {
                if ($null -ne $User) {
                    $ret += [NtApiDotNet.Win32.Security.Audit.AuditSecurityUtils]::GetPerUserCategory($User, $cat)
                } else {
                    $ret += [NtApiDotNet.Win32.Security.Audit.AuditSecurityUtils]::GetCategory($cat)
                }
            }
            $ret
        }
        "FromCategoryGuid" {
            $ret = @()
            foreach($cat in $CategoryGuid) {
                if ($null -ne $User) {
                    $ret += [NtApiDotNet.Win32.Security.Audit.AuditSecurityUtils]::GetPerUserCategory($User, $cat)
                } else {
                    $ret += [NtApiDotNet.Win32.Security.Audit.AuditSecurityUtils]::GetCategory($cat)
                }
            }
            $ret
        }
        "FromSubCategoryName" {
            Get-NtAuditPolicy -ExpandCategory -User $User | Where-Object Name -in $SubCategoryName
        }
        "FromSubCategoryGuid" {
            Get-NtAuditPolicy -ExpandCategory -User $User | Where-Object Id -in $SubCategoryGuid
        }
    }
    if ($ExpandCategory) {
        $cats | Select-Object -ExpandProperty SubCategories | Write-Output
    } else {
        $cats | Write-Output
    }
}

<#
.SYNOPSIS
Set the advanced audit policy information.
.DESCRIPTION
This cmdlet sets advanced audit policy information.
.PARAMETER Category
Specify the category type.
.PARAMETER CategoryGuid
Specify the category type GUID.
.PARAMETER Policy
Specify the policy to set.
.PARAMETER PassThru
Specify to pass through the category objects.
.PARAMETER User
Specify the SID of the user to set a per-user audit policy.
.PARAMETER UserPolicy
Specify the policy to set for a per-user policy.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Audit.AuditSubCategory
NtApiDotNet.Win32.Security.Audit.AuditPerUserSubCategory
.EXAMPLE
Set-NtAuditPolicy -Category 
Get all audit policy categories.
.EXAMPLE
Get-NtAuditPolicy -Category ObjectAccess
Get the ObjectAccess audit policy category
.EXAMPLE
Get-NtAuditPolicy -Category ObjectAccess -Expand
Get the ObjectAccess audit policy category and return the SubCategory policies.
#>
function Set-NtAuditPolicy {
    [CmdletBinding(DefaultParameterSetName = "FromCategoryType", SupportsShouldProcess)]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromCategoryType")]
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromCategoryTypeUser")]
        [NtApiDotNet.Win32.Security.Audit.AuditPolicyEventType[]]$Category,
        [parameter(Mandatory, ParameterSetName = "FromCategoryGuid")]
        [parameter(Mandatory, ParameterSetName = "FromCategoryGuidUser")]
        [Guid[]]$CategoryGuid,
        [parameter(Mandatory, ParameterSetName = "FromSubCategoryName")]
        [parameter(Mandatory, ParameterSetName = "FromSubCategoryNameUser")]
        [string[]]$SubCategoryName,
        [parameter(Mandatory, ParameterSetName = "FromSubCategoryGuid")]
        [parameter(Mandatory, ParameterSetName = "FromSubCategoryUser")]
        [guid[]]$SubCategoryGuid,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromCategoryType")]
        [parameter(Mandatory, Position = 1, ParameterSetName="FromCategoryGuid")]
        [parameter(Mandatory, Position = 1, ParameterSetName="FromSubCategoryName")]
        [parameter(Mandatory, Position = 1, ParameterSetName="FromSubCategoryGuid")]
        [NtApiDotNet.Win32.Security.Audit.AuditPolicyFlags]$Policy,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromCategoryTypeUser")]
        [parameter(Mandatory, Position = 1, ParameterSetName="FromCategoryGuidUser")]
        [parameter(Mandatory, Position = 1, ParameterSetName="FromSubCategoryNameUser")]
        [parameter(Mandatory, Position = 1, ParameterSetName="FromSubCategoryGuidUser")]
        [NtApiDotNet.Win32.Security.Audit.AuditPerUserPolicyFlags]$UserPolicy,
        [parameter(Mandatory, ParameterSetName="FromCategoryTypeUser")]
        [parameter(Mandatory, ParameterSetName="FromCategoryGuidUser")]
        [parameter(Mandatory, ParameterSetName="FromSubCategoryNameUser")]
        [parameter(Mandatory, ParameterSetName="FromSubCategoryGuidUser")]
        [NtApiDotNet.Sid]$User,
        [switch]$PassThru
    )
    if (!(Test-NtTokenPrivilege SeSecurityPrivilege)) {
        Write-Warning "SeSecurityPrivilege not enabled. Might not change Audit settings."
    }

    $cats = switch -Wildcard ($PSCmdlet.ParameterSetName) {
        "FromCategoryType*" {
            Get-NtAuditPolicy -Category $Category -ExpandCategory -User $User
        }
        "FromCategoryGuid*" {
            Get-NtAuditPolicy -CategoryGuid $CategoryGuid -ExpandCategory -User $User
        }
        "FromSubCategoryName*" {
            Get-NtAuditPolicy -SubCategoryName $SubCategoryName -User $User
        }
        "FromSubCategoryGuid*" {
            Get-NtAuditPolicy -SubCategoryGuid $SubCategoryGuid -User $User
        }
    }

    foreach($cat in $cats) {
        $policy_value = if ($null -eq $User) {
            $Policy
        }
        else {
            $UserPolicy
        }
        if ($PSCmdlet.ShouldProcess($cat.Name, "Set $policy_value")) {
            $cat.SetPolicy($policy_value)
            if ($PassThru) {
                Write-Output $cat
            }
        }
    }
}

<#
.SYNOPSIS
Get advanced audit policy security descriptor information.
.DESCRIPTION
This cmdlet gets advanced audit policy security descriptor information.
.PARAMETER GlobalSacl
Specify the type of object to query the global SACL.
.INPUTS
None
.OUTPUTS
NtApiDotNet.SecurityDescriptor
.EXAMPLE
Get-NtAuditSecurity
Get the Audit security descriptor.
.EXAMPLE
Get-NtAuditSecurity -GlobalSacl File
Get the File global SACL.
#>
function Get-NtAuditSecurity {
    [CmdletBinding(DefaultParameterSetName = "FromSecurityDescriptor")]
    param (
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromGlobalSacl")]
        [NtApiDotNet.Win32.Security.Audit.AuditGlobalSaclType]$GlobalSacl
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromSecurityDescriptor" {
            [NtApiDotNet.Win32.Security.Audit.AuditSecurityUtils]::QuerySecurity() | Write-Output
        }
        "FromGlobalSacl" {
            [NtApiDotNet.Win32.Security.Audit.AuditSecurityUtils]::QueryGlobalSacl($GlobalSacl) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Set advanced audit policy security descriptor information.
.DESCRIPTION
This cmdlet sets advanced audit policy security descriptor information.
.PARAMETER GlobalSacl
Specify the type of object to set the global SACL.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-NtAuditSecurity -SecurityDescriptor $sd
Set the Audit security descriptor.
.EXAMPLE
Set-NtAuditSecurity -SecurityDescriptor $sd -GlobalSacl File
Set the File global SACL.
#>
function Set-NtAuditSecurity {
    [CmdletBinding(DefaultParameterSetName = "FromSecurityDescriptor", SupportsShouldProcess)]
    param (
        [parameter(Mandatory, Position = 0)]
        [NtApiDotNet.SecurityDescriptor]$SecurityDescriptor,
        [parameter(Mandatory, Position = 1, ParameterSetName = "FromGlobalSacl")]
        [NtApiDotNet.Win32.Security.Audit.AuditGlobalSaclType]$GlobalSacl
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromSecurityDescriptor" {
            if ($PSCmdlet.ShouldProcess("$SecurityDescriptor", "Set Audit SD")) {
                [NtApiDotNet.Win32.Security.Audit.AuditSecurityUtils]::SetSecurity($SecurityDescriptor)
            }
        }
        "FromGlobalSacl" {
            if ($PSCmdlet.ShouldProcess("$SecurityDescriptor", "Set $GlobalSacl SACL")) {
                [NtApiDotNet.Win32.Security.Audit.AuditSecurityUtils]::SetGlobalSacl($GlobalSacl, $SecurityDescriptor)
            }
        }
    }
}

<#
.SYNOPSIS
Get logon sessions for current system.
.DESCRIPTION
This cmdlet gets the active logon sessions for the current system.
.PARAMETER LogonId
Specify the Logon ID for the session.
.PARAMETER Token
Specify a Token to get the session for.
.PARAMETER IdOnly
Specify to only get the Logon ID rather than full details.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.LogonSession
NtApiDotNet.Luid
.EXAMPLE
Get-NtLogonSession
Get all accessible logon sessions.
.EXAMPLE
Get-NtLogonSession -LogonId 123456
Get logon session with ID 123456
.EXAMPLE
Get-NtLogonSession -Token $token
Get logon session from Token Authentication ID.
.EXAMPLE
Get-NtLogonSession -IdOnly
Get all logon sesion IDs only.
#>
function Get-NtLogonSession {
    [CmdletBinding(DefaultParameterSetName = "All")]
    param (
        [parameter(Mandatory, ParameterSetName = "FromLogonId")]
        [NtApiDotNet.Luid]$LogonId,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromToken")]
        [NtApiDotNet.NtToken]$Token,
        [parameter(ParameterSetName = "All")]
        [switch]$IdOnly
    )
    switch($PSCmdlet.ParameterSetName) {
        "All" {
            if ($IdOnly) {
                [NtApiDotNet.Win32.LogonUtils]::GetLogonSessionIds() | Write-Output
            } else {
                [NtApiDotNet.Win32.LogonUtils]::GetLogonSessions() | Write-Output
            }
        }
        "FromLogonId" {
            [NtApiDotNet.Win32.LogonUtils]::GetLogonSession($LogonId) | Write-Output
        }
        "FromToken" {
            [NtApiDotNet.Win32.LogonUtils]::GetLogonSession($Token.AuthenticationId) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get account rights for current system.
.DESCRIPTION
This cmdlet gets account rights for the current system.
.PARAMETER Type
Specify the type of account rights to query.
.PARAMETER Sid
Specify a SID to get all account rights for.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.AccountRight
.EXAMPLE
Get-NtAccountRight
Get all account rights.
.EXAMPLE
Get-NtAccountRight -Type Privilege
Get all privilege account rights.
.EXAMPLE
Get-NtAccountRight -Type Logon
Get all logon account rights.
.EXAMPLE
Get-NtAccountRight -SID $sid
Get account rights for SID.
.EXAMPLE
Get-NtAccountRight -KnownSid World
Get account rights for known SID.
.EXAMPLE
Get-NtAccountRight -Name "Everyone"
Get account rights for group name.
#>
function Get-NtAccountRight {
    [CmdletBinding(DefaultParameterSetName = "All")]
    param (
        [parameter(Position = 0, ParameterSetName = "All")]
        [NtApiDotNet.Win32.AccountRightType]$Type = "All",
        [parameter(Mandatory, ParameterSetName = "FromSid")]
        [NtApiDotNet.Sid]$Sid,
        [parameter(Mandatory, ParameterSetName = "FromKnownSid")]
        [NtApiDotNet.KnownSidValue]$KnownSid,
        [parameter(Mandatory, ParameterSetName = "FromName")]
        [string]$Name
    )

    switch($PSCmdlet.ParameterSetName) {
        "All" {
            [NtApiDotNet.Win32.LogonUtils]::GetAccountRights($Type) | Write-Output
        }
        "FromSid" {
            [NtApiDotNet.Win32.LogonUtils]::GetAccountRights($Sid) | Write-Output
        }
        "FromKnownSid" {
            [NtApiDotNet.Win32.LogonUtils]::GetAccountRights((Get-NtSid -KnownSid $KnownSid)) | Write-Output
        }
        "FromName" {
            [NtApiDotNet.Win32.LogonUtils]::GetAccountRights((Get-NtSid -Name $Name)) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get SIDs for an account right for current system.
.DESCRIPTION
This cmdlet gets SIDs for an account rights for the current system.
.PARAMETER Privilege
Specify a privileges to query.
.PARAMETER Logon
Specify a logon rights to query.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Sid
.EXAMPLE
Get-NtAccountRightSid -Privilege SeBackupPrivilege
Get all SIDs for SeBackupPrivilege.
.EXAMPLE
Get-NtAccountRightSid -Logon SeInteractiveLogonRight
Get all SIDs which can logon interactively.
#>
function Get-NtAccountRightSid {
    [CmdletBinding(DefaultParameterSetName = "Privilege")]
    param (
        [parameter(Mandatory, ParameterSetName = "FromPrivilege")]
        [NtApiDotNet.TokenPrivilegeValue]$Privilege,
        [parameter(Mandatory, ParameterSetName = "FromLogon")]
        [NtApiDotNet.Win32.Security.Policy.AccountRightLogonType]$Logon
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromPrivilege" {
            [NtApiDotNet.Win32.LogonUtils]::GetAccountRightSids($Privilege) | Write-Output
        }
        "FromLogon" {
            [NtApiDotNet.Win32.LogonUtils]::GetAccountRightSids($Logon) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get current console sessions for the system.
.DESCRIPTION
This cmdlet gets current console sessions for the system.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.ConsoleSession
.EXAMPLE
Get-NtConsoleSession
Get all Console Sesssions.
#>
function Get-NtConsoleSession {
    [NtApiDotNet.Win32.Win32Utils]::GetConsoleSessions() | Write-Output
}

<#
.SYNOPSIS
Get a service principal name.
.DESCRIPTION
This cmdlet gets SPN for a string.
.PARAMETER Name
Specify the SPN.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.ServicePrincipalName
.EXAMPLE
Get-ServicePrincipalName -Name "HTTP/www.domain.com"
Get the SPN from a string.
#>
function Get-ServicePrincipalName {
    param (
        [parameter(Mandatory, Position = 0)]
        [string]$Name
    )
    [NtApiDotNet.Win32.Security.Authentication.ServicePrincipalName]::Parse($Name) | Write-Output
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
NtApiDotNet.Luid
.EXAMPLE
Get-NtTokenId
Get the Token ID field.
.EXAMPLE
Get-NtTokenOwner -Token $token
Get Token ID on an explicit token object.
.EXAMPLE
Get-NtTokenOwner -Authentication
Get the token's Authentication ID.
.EXAMPLE
Get-NtTokenOwner -Origin
Get the token's Origin ID.
#>
function Get-NtTokenId {
    [CmdletBinding(DefaultParameterSetName="FromId")]
    Param(
        [NtApiDotNet.NtToken]$Token,
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
Get a MD4 hash of a byte array or string.
.DESCRIPTION
This cmdlet calculates the MD4 hash of a byte array or string.
.PARAMETER Bytes
Specify a byte array.
.PARAMETER String
Specify string.
.PARAMETER Encoding
Specify string encoding. Default to Unicode.
.INPUTS
None
.OUTPUTS
byte[]
.EXAMPLE
Get-MD4Hash -String "ABC"
Get the MD4 hash of the string ABC in unicode.
.EXAMPLE
Get-MD4Hash -String "ABC" -Encoding "ASCII"
Get the MD4 hash of the string ABC in ASCII.
.EXAMPLE
Get-MD4Hash -Bytes @(0, 1, 2, 3)
Get the MD4 hash of a byte array.
#>
function Get-MD4Hash {
    [CmdletBinding(DefaultParameterSetName="FromString")]
    Param(
        [AllowEmptyString()]
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromString")]
        [string]$String,
        [Parameter(Position = 1, ParameterSetName="FromString")]
        [string]$Encoding = "Unicode",
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromBytes")]
        [byte[]]$Bytes
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromString" {
            $enc = [System.Text.Encoding]::GetEncoding($Encoding)
            [NtApiDotNet.Utilities.Security.MD4]::CalculateHash($String, $enc)
        }
        "FromBytes" {
            [NtApiDotNet.Utilities.Security.MD4]::CalculateHash($Bytes)
        }
    }
}

<#
.SYNOPSIS
Formats ASN.1 DER data to a string.
.DESCRIPTION
This cmdlet formats ASN.1 DER data to a string either from a byte array or a file.
.PARAMETER Bytes
Specify a byte array containing the DER data.
.PARAMETER Path
Specify file containing the DER data.
.PARAMETER Depth
Specify initialize indentation depth.
.INPUTS
None
.OUTPUTS
string
.EXAMPLE
Format-ASN1DER -Bytes $ba
Format the byte array with ASN.1 DER data.
.EXAMPLE
Format-ASN1DER -Bytes $ba -Depth 2
Format the byte array with ASN.1 DER data with indentation depth of 2.
.EXAMPLE
Format-ASN1DER -Path file.bin
Format the file containing ASN.1 DER data.
#>
function Format-ASN1DER {
    [CmdletBinding(DefaultParameterSetName="FromBytes")]
    Param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromPath")]
        [string]$Path,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromBytes")]
        [byte[]]$Bytes,
        [int]$Depth = 0
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromPath" {
            [NtApiDotNet.Utilities.ASN1.ASN1Utils]::FormatDER($Path, $Depth)
        }
        "FromBytes" {
            [NtApiDotNet.Utilities.ASN1.ASN1Utils]::FormatDER($Bytes, $Depth)
        }
    }
}

<#
.SYNOPSIS
Exports keys to a Kerberos KeyTab file file.
.DESCRIPTION
This cmdlet exports keys to a Kerberos KeyTab file file.
.PARAMETER Key
List of keys to write to the file.
.PARAMETER Path
The path to the file to export.
.INPUTS
NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey
.OUTPUTS
None
#>
function Export-KerberosKeyTab {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Path,
        [Parameter(Position = 1, Mandatory, ValueFromPipeline)]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey[]]$Key
    )

    BEGIN {
        $keys = @()
    }

    PROCESS {
        foreach($k in $Key) {
            $keys += $k
        }
    }

    END {
        $key_arr = [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey[]]$keys
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosUtils]::GenerateKeyTabFile($key_arr) `
                | Set-Content -Path $Path -Encoding Byte
    }
}

<#
.SYNOPSIS
Imports a Kerberos KeyTab file into a list of keys.
.DESCRIPTION
This cmdlet imports a Kerberos KeyTab file into a list of keys.
.PARAMETER Path
The path to the file to import.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey
#>
function Import-KerberosKeyTab {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Path
    )

    $Path = Resolve-Path -Path $Path -ErrorAction Stop
    [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosUtils]::ReadKeyTabFile($Path) | Write-Output
}

<#
.SYNOPSIS
Gets a Kerberos Key from a raw key or password.
.DESCRIPTION
This cmdlet gets a Kerberos Key from a raw key or password.
.PARAMETER Password
The password to convert to a key.
.PARAMETER KeyType
The key encryption type.
.PARAMETER Iterations
The number of iterations for the key derivation.
.PARAMETER Principal
The principal associated with the key.
.PARAMETER Salt
The salt for the key, if not specified will try and derive from the principal.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey
#>
function Get-KerberosKey {
    [CmdletBinding(DefaultParameterSetName="FromPassword")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromPassword")]
        [string]$Password,
        [Parameter(Position = 0, Mandatory, ParameterSetName="FromKey")]
        [byte[]]$Key,
        [Parameter(Mandatory, ParameterSetName="FromBase64Key")]
        [string]$Base64Key,
        [Parameter(Position = 1, Mandatory, ParameterSetName="FromPassword")]
        [Parameter(Position = 1, Mandatory, ParameterSetName="FromKey")]
        [Parameter(Mandatory, ParameterSetName="FromBase64Key")]
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosEncryptionType]$KeyType,
        [Parameter(ParameterSetName="FromPassword")]
        [int]$Interations = 4096,
        [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosNameType]$NameType = "PRINCIPAL",
        [Parameter(Position = 2, Mandatory, ParameterSetName="FromPassword")]
        [Parameter(Position = 2, Mandatory, ParameterSetName="FromKey")]
        [Parameter(Mandatory, ParameterSetName="FromBase64Key")]
        [string]$Principal,
        [Parameter(ParameterSetName="FromPassword")]
        [string]$Salt,
        [uint32]$Version = 1,
        [Parameter(ParameterSetName="FromKey")]
        [Parameter(ParameterSetName="FromBase64Key")]
        [DateTime]$Timestamp = [DateTime]::Now
    )

    $k = switch($PSCmdlet.ParameterSetName) {
        "FromPassword" {
            [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]::DeriveKey($KeyType, $Password, $Interations, $NameType, $Principal, $Salt, $Version)
        }
        "FromKey" {
            [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]::new($KeyType, $Key, $NameType, $Principal, $Timestamp, $Version)
        }
        "FromBase64Key" {
            $Key = [System.Convert]::FromBase64String($Base64Key)
            [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosAuthenticationKey]::new($KeyType, $Key, $NameType, $Principal, $Timestamp, $Version)
        }
    }
    $k | Write-Output
}

<#
.SYNOPSIS
Decrypt an Authentication Token.
.DESCRIPTION
This cmdlet attempts to decrypt an authentication token. The call will return the decrypted token.
This is primarily for Kerberos.
.PARAMETER Key
Specify a keys for decryption.
.PARAMETER Token
The authentication token to decrypt.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.AuthenticationToken
#>
function Unprotect-AuthToken {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.AuthenticationToken]$Token,
        [Parameter(Position = 1, Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.AuthenticationKey[]]$Key
    )
    $Token.Decrypt($Key) | Write-Output
}

<#
.SYNOPSIS
Get Kerberos Ticket.
.DESCRIPTION
This cmdlet gets a kerberos Ticket, or multiple tickets.
.PARAMETER LogonId
Specify a logon ID to query for tickets.
.PARAMETER LogonSession
Specify a logon session to query for tickets.
.PARAMETER TargetName
Specify a target name to query for a ticket. If it doesn't exist get a new one.
.PARAMETER CacheOnly
Specify to only lookup the TargetName in the cache.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosExternalTicket
#>
function Get-KerberosTicket {
    [CmdletBinding(DefaultParameterSetName="CurrentLuid")]
    Param(
        [Parameter(Position = 0, ParameterSetName="FromLuid", Mandatory)]
        [NtApiDotNet.Luid]$LogonId,
        [Parameter(Position = 0, ParameterSetName="FromLogonSession", ValueFromPipeline, Mandatory)]
        [NtApiDotNet.Win32.Security.Authentication.LogonSession[]]$LogonSession,
        [Parameter(Position = 0, ParameterSetName="FromTarget", Mandatory)]
        [string]$TargetName,
        [Parameter(ParameterSetName="FromTarget")]
        [switch]$CacheOnly
    )

    PROCESS {
        switch($PSCmdlet.ParameterSetName) {
            "CurrentLuid" {
                [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCache() | Write-Output
            }
            "FromLuid" {
                [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCache($LogonId) | Write-Output
            }
            "FromLogonSession" {
                foreach($l in $LogonSession) {
                    [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::QueryTicketCache($l.LogonId) | Write-Output
                }
            }
            "FromTarget" {
                [NtApiDotNet.Win32.Security.Authentication.Kerberos.KerberosTicketCache]::GetTicket($LogonId, $CacheOnly) | Write-Output
            }
        }
    }
}

<#
.SYNOPSIS
Get NDR complex types from memory.
.DESCRIPTION
This cmdlet parses NDR complex type information from a location in memory.
.PARAMETER PicklingInfo
Specify pointer to the MIDL_TYPE_PICKLING_INFO structure.
.PARAMETER StubDesc
Specify pointer to the MIDL_STUB_DESC structure.
.PARAMETER StublessProxy
Specify pointer to the MIDL_STUBLESS_PROXY_INFO structure.
.PARAMETER OffsetTable
Specify pointer to type offset table.
.PARAMETER TypeIndex
Specify list of type index into type offset table.
.PARAMETER TypeFormat
Specify list of type format string addresses for the types.
.PARAMETER TypeOffset
Specify list of type offsets into the format string for the types.
.PARAMETER Process
Specify optional process which contains the types.
.PARAMETER Module
Specify optional module base address for the types. If set all pointers
are relative offsets from the module address.
.INPUTS
None
.OUTPUTS
NdrComplexTypeReference[]
#>
function Get-NdrComplexType {
    [CmdletBinding(DefaultParameterSetName="FromDecode3")]
    Param(
        [Parameter(Mandatory)]
        [long]$PicklingInfo,
        [Parameter(Mandatory, ParameterSetName = "FromDecode2")]
        [Parameter(Mandatory, ParameterSetName = "FromDecode2Offset")]
        [long]$StubDesc,
        [Parameter(Mandatory, ParameterSetName = "FromDecode2")]
        [long[]]$TypeFormat,
        [Parameter(Mandatory, ParameterSetName = "FromDecode2Offset")]
        [int[]]$TypeOffset,
        [Parameter(Mandatory, ParameterSetName = "FromDecode3")]
        [long]$StublessProxy,
        [Parameter(Mandatory, ParameterSetName = "FromDecode3")]
        [long]$OffsetTable,
        [Parameter(Mandatory, ParameterSetName = "FromDecode3")]
        [int[]]$TypeIndex,
        [NtApiDotNet.Win32.SafeLoadLibraryHandle]$Module,
        [NtApiDotNet.NtProcess]$Process,
        [NtApiDotNet.Ndr.NdrParserFlags]$Flags = "IgnoreUserMarshal"
    )

    $base_address = 0
    if ($null -ne $Module) {
        $base_address = $Module.DangerousGetHandle().ToInt64()
    }

    switch($PSCmdlet.ParameterSetName) {
        "FromDecode2" {
            $type_offset = $TypeFormat | % { $_ + $base_address }
            [NtApiDotNet.Ndr.NdrParser]::ReadPicklingComplexTypes($Process, $PicklingInfo+$base_address,`
                $StubDesc+$base_address, $type_offset, $Flags) | Write-Output
        }
        "FromDecode2Offset" {
            [NtApiDotNet.Ndr.NdrParser]::ReadPicklingComplexTypes($Process, $PicklingInfo+$base_address,`
                $StubDesc+$base_address, $TypeOffset, $Flags) | Write-Output
        }
        "FromDecode3" {
            [NtApiDotNet.Ndr.NdrParser]::ReadPicklingComplexTypes($Process, $PicklingInfo+$base_address,`
                $StublessProxy+$base_address, $OffsetTable+$base_address, $TypeIndex, $Flags) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Get user SID for a process.
.DESCRIPTION
This cmdlet will get the user SID for a process.
.PARAMETER Process
The process object.
.PARAMETER ProcessId
The PID of the process.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Sid
.EXAMPLE
Get-NtProcessUser -ProcessId 1234
Get user SID for process ID 1234.
.EXAMPLE
Get-NtProcessUser -Process $p
Get user SID for process.
#>
function Get-NtProcessUser {
    [CmdletBinding(DefaultParameterSetName = "FromProcessId")]
    Param(
        [parameter(ParameterSetName = "FromProcessId", Position = 0, Mandatory)]
        [alias("pid")]
        [int]$ProcessId,
        [parameter(ParameterSetName = "FromProcess", Mandatory)]
        [NtApiDotNet.NtProcess]$Process
    )
    Set-NtTokenPrivilege -Privilege SeDebugPrivilege -WarningAction SilentlyContinue
    switch ($PSCmdlet.ParameterSetName) {
        "FromProcessId" {
            Use-NtObject($p = Get-NtProcess -ProcessId $ProcessId -Access QueryLimitedInformation) {
                Get-NtProcessUser -Process $p | Write-Output
            }
        }
        "FromProcess" {
            $Process.User | Write-Output
        }
    }
}