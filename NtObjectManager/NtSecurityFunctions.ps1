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
        [NtCoreLib.Security.Authorization.INtObjectSecurity]$Object,
        [Parameter(ParameterSetName = "FromObject")]
        [switch]$ReadOnly,
        [Parameter(Position = 0, ParameterSetName = "FromAccessCheck", Mandatory = $true)]
        [NtObjectManager.Cmdlets.Accessible.CommonAccessCheckResult]$AccessCheckResult,
        [Parameter(Position = 0, ParameterSetName = "FromSecurityDescriptor", Mandatory = $true)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, ParameterSetName = "FromSecurityDescriptor")]
        [NtCoreLib.NtType]$Type,
        [Parameter(ParameterSetName = "FromSecurityDescriptor")]
        [string]$Name = "Object",
        [Parameter(ParameterSetName = "FromSecurityDescriptor")]
        [switch]$Container,
        [switch]$Wait
    )

    switch ($PsCmdlet.ParameterSetName) {
        "FromObject" {
            if (!$Object.IsAccessMaskGranted([NtCoreLib.GenericAccessRights]::ReadControl)) {
                Write-Error "Object doesn't have Read Control access."
                return
            }
            # If an ALPC Port or not an NtObject pass as an SD.
            if (($Object.NtType.Name -eq "ALPC Port" ) -or !($Object -is [NtCoreLib.NtObject])) {
                Show-NtSecurityDescriptor $Object.SecurityDescriptor $Object.NtType -Name $Object.ObjectName -Wait:$Wait
                return
            }
            Use-NtObject($obj = $Object.Duplicate()) {
                $cmdline = "ViewSecurityDescriptor {0}" -f $obj.Handle.DangerousGetHandle()
                if ($ReadOnly) {
                    $cmdline += " --readonly"
                }
                [NtObjectManager.Utils.PSUtils]::StartUtilityProcess("$PSScriptRoot\ViewSecurityDescriptor.exe", $cmdline, $Wait, $obj)
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
            $cmdline = "ViewSecurityDescriptor `"$Name`" -$sd `"$($Type.Name)`" $Container"
            [NtObjectManager.Utils.PSUtils]::StartUtilityProcess("$PSScriptRoot\ViewSecurityDescriptor.exe", $cmdline, $Wait)
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
OUTPUTS
NtCoreLib.Security.Token.SecurityQualityOfService
#>
function New-NtSecurityQualityOfService {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [NtCoreLib.Security.Token.SecurityImpersonationLevel]$ImpersonationLevel,
        [NtCoreLib.Security.Token.SecurityContextTrackingMode]$ContextTrackingMode = "Static",
        [switch]$EffectiveOnly
    )

    [NtCoreLib.Security.Token.SecurityQualityOfService]::new($ImpersonationLevel, $ContextTrackingMode, $EffectiveOnly)
}

function Format-NtAce {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline)]
        [NtCoreLib.Security.Authorization.Ace]$Ace,
        [Parameter(Position = 1, Mandatory = $true)]
        [NtCoreLib.NtType]$Type,
        [switch]$MapGeneric,
        [switch]$Summary,
        [switch]$Container,
        [switch]$SDKName,
        [switch]$ResolveObjectType,
        [string]$Domain
    )

    PROCESS {
        $mask = $ace.Mask
        $access_name = "Access"
        $mask_str = if ($ace.Type -eq "MandatoryLabel") {
            [NtCoreLib.Security.NtSecurity]::AccessMaskToString($mask.ToMandatoryLabelPolicy(), $SDKName)
            $access_name = "Policy"
        }
        else {
            $Type.AccessMaskToString($Container, $mask, $MapGeneric, $SDKName)
        }

        if ($SDKName) {
            $ace_type = [NtCoreLib.Security.NtSecurity]::AceTypeToSDKName($ace.Type)
            $ace_flags = [NtCoreLib.Security.NtSecurity]::AceFlagsToSDKName($ace.Flags)
        } else {
            $ace_type = $ace.Type
            $ace_flags = $ace.Flags
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
                    $name = $ace.ObjectType
                    if ($ResolveObjectType) {
                        $name = $ace.GetObjectTypeName($Domain, $false)
                    }
                    $cond += "(OBJ:$name)"
                }
                if ($null -ne $ace.InheritedObjectType) {
                    $name = $ace.InheritedObjectType
                    if ($ResolveObjectType) {
                        $name = $ace.GetInheritedObjectTypeName($Domain)
                    }
                    $cond += "(IOBJ:$name)"
                }
            }

            Write-Output "$($ace.Sid.Name): ($ace_type)($ace_flags)($mask_str)$cond"
        }
        else {
            Write-Output " - Type  : $ace_type"
            Write-Output " - Name  : $($ace.Sid.Name)"
            Write-Output " - SID   : $($ace.Sid)"
            if ($ace.IsCompoundAce) {
                Write-Output " - ServerName: $($ace.ServerSid.Name)"
                Write-Output " - ServerSID : $($ace.ServerSid)"
            }
            Write-Output " - Mask  : 0x$($mask.ToString("X08"))"
            Write-Output " - $($access_name): $mask_str"
            Write-Output " - Flags : $ace_flags"
            if ($ace.IsConditionalAce) {
                Write-Output " - Condition: $($ace.Condition)"
            }
            if ($ace.IsResourceAttributeAce) {
                Write-Output " - Attribute: $($ace.ResourceAttribute.ToSddl())"
            }
            if ($ace.IsObjectAce) {
                if ($null -ne $ace.ObjectType) {
                    $name = $ace.ObjectType
                    if ($ResolveObjectType) {
                        $name = $ace.GetObjectTypeName($Domain, $false)
                    }
                    Write-Output " - ObjectType: $name"
                }
                if ($null -ne $ace.InheritedObjectType) {
                    $name = $ace.InheritedObjectType
                    if ($ResolveObjectType) {
                        $name = $ace.GetInheritedObjectTypeName($Domain)
                    }
                    Write-Output " - InheritedObjectType: $name"
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
        [NtCoreLib.Security.Authorization.Acl]$Acl,
        [Parameter(Position = 1, Mandatory)]
        [NtCoreLib.NtType]$Type,
        [Parameter(Position = 2, Mandatory)]
        [string]$Name,
        [switch]$MapGeneric,
        [switch]$AuditOnly,
        [switch]$Summary,
        [switch]$Container,
        [switch]$SDKName,
        [switch]$ResolveObjectType,
        [string]$Domain
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
            $Acl | Where-Object IsAuditAce | Format-NtAce -Type $Type -MapGeneric:$MapGeneric -Summary:$Summary -Container:$Container -SDKName:$SDKName -ResolveObjectType:$ResolveObjectType -Domain:$Domain
        }
        else {
            $Acl | Format-NtAce -Type $Type -MapGeneric:$MapGeneric -Summary:$Summary -Container:$Container -SDKName:$SDKName -ResolveObjectType:$ResolveObjectType -Domain:$Domain
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
.PARAMETER AsSddl
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
.PARAMETER SDKName
Specify to format the security descriptor using SDK names where available.
.PARAMETER ResolveObjectType
Specify to try and resolve the object type GUID from the local Active Directory.
.PARAMETER Domain
Specify to indicate the domain to query the object type from when resolving. Defaults to the current domain.
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
Format-NtSecurityDescriptor -Object $obj -AsSddl
Format the security descriptor of an object as SDDL.
.EXAMPLE
Format-NtSecurityDescriptor -Object $obj -AsSddl -SecurityInformation Dacl, Label
Format the security descriptor of an object as SDDL with only DACL and Label.
#>
function Format-NtSecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName = "FromObject")]
    Param(
        [Parameter(Position = 0, ParameterSetName = "FromObject", Mandatory, ValueFromPipeline)]
        [NtCoreLib.Security.Authorization.INtObjectSecurity]$Object,
        [Parameter(Position = 0, ParameterSetName = "FromSecurityDescriptor", Mandatory, ValueFromPipeline)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 0, ParameterSetName = "FromAccessCheck", Mandatory, ValueFromPipeline)]
        [NtObjectManager.Cmdlets.Accessible.CommonAccessCheckResult]$AccessCheckResult,
        [Parameter(Position = 0, ParameterSetName = "FromAcl", Mandatory)]
        [AllowEmptyCollection()]
        [NtCoreLib.Security.Authorization.Acl]$Acl,
        [Parameter(ParameterSetName = "FromAcl")]
        [switch]$AuditOnly,
        [Parameter(Position = 1, ParameterSetName = "FromSecurityDescriptor")]
        [Parameter(Position = 1, ParameterSetName = "FromAcl")]
        [NtCoreLib.NtType]$Type,
        [switch]$Container,
        [Parameter(Position = 0, ParameterSetName = "FromPath", Mandatory, ValueFromPipeline)]
        [string]$Path,
        [parameter(ParameterSetName = "FromPath")]
        [NtCoreLib.NtObject]$Root,
        [NtCoreLib.Security.Authorization.SecurityInformation]$SecurityInformation = "AllBasic",
        [switch]$MapGeneric,
        [alias("ToSddl")]
        [switch]$AsSddl,
        [switch]$Summary,
        [switch]$ShowAll,
        [switch]$HideHeader,
        [Parameter(ParameterSetName = "FromSecurityDescriptor")]
        [Parameter(ParameterSetName = "FromAcl")]
        [string]$DisplayPath = "",
        [switch]$SDKName,
        [switch]$ResolveObjectType,
        [string]$Domain
    )

    PROCESS {
        try {
            $sd, $t, $n = switch ($PsCmdlet.ParameterSetName) {
                "FromObject" {
                    $access = Get-NtAccessMask -SecurityInformation $SecurityInformation -ToGenericAccess
                    if (!$Object.IsAccessMaskGranted($access)) {
                        Write-Error "Object doesn't have $access access."
                        return
                    }
                    ($Object.GetSecurityDescriptor($SecurityInformation), $Object.NtType, $Object.ObjectName)
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
                $si = [NtCoreLib.Security.Authorization.SecurityInformation]::All
            }

            if ($AsSddl) {
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
                $sd_control = $sd.Control
                if ($SDKName) {
                    $sd_control = [NtCoreLib.Security.NtSecurity]::ControlFlagsToSDKName($sd_control)
                }
                Write-Output "Control: $sd_control"
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
                Format-NtAcl -Acl $sd.Dacl -Type $t -Name "<DACL>" -MapGeneric:$MapGeneric -Summary:$Summary -Container:$Container -SDKName:$SDKName -ResolveObjectType:$ResolveObjectType -Domain $Domain
            }
            if (($sd.HasAuditAce -or $sd.SaclNull) -and (($si -band "Sacl") -ne 0)) {
                Format-NtAcl -Acl $sd.Sacl -Type $t -Name "<SACL>" -MapGeneric:$MapGeneric -AuditOnly -Summary:$Summary -Container:$Container -SDKName:$SDKName -ResolveObjectType:$ResolveObjectType -Domain $Domain
            }

            if (($si -band "Label") -ne 0) {
                $label = $sd.FindAllSaclAce("MandatoryLabel", $true)
                if ($label.Count -gt 0) {
                    Write-Output "<Mandatory Label>"
                    $label | Format-NtAce -Type $t -Summary:$Summary -Container:$Container -SDKName:$SDKName
                }
            }
            if (($si -band "ProcessTrustLabel") -ne 0) {
                $trust = $sd.FindAllSaclAce("ProcessTrustLabel", $true)
                if ($trust.Count -gt 0) {
                    Write-Output "<Process Trust Label>"
                    $trust | Format-NtAce -Type $t -Summary:$Summary -Container:$Container -SDKName:$SDKName
                }
            }
            if (($si -band "Attribute") -ne 0) {
                $attrs = $sd.FindAllSaclAce("ResourceAttribute", $true)
                if ($attrs.Count -gt 0) {
                    Write-Output "<Resource Attributes>"
                    $attrs | Format-NtAce -Type $t -Summary:$Summary -Container:$Container -SDKName:$SDKName
                }
            }
            if (($si -band "AccessFilter") -ne 0) {
                $filters = $sd.FindAllSaclAce("AccessFilter", $true)
                if ($filters.Count -gt 0) {
                    Write-Output "<Access Filters>"
                    $filters | Format-NtAce -Type $t -Summary:$Summary -Container:$Container -SDKName:$SDKName
                }
            }
            if (($si -band "Scope") -ne 0) {
                $scope = $sd.FindAllSaclAce("ScopedPolicyId", $true)
                if ($scope.Count -gt 0) {
                    Write-Output "<Scoped Policy ID>"
                    $scope | Format-NtAce -Type $t -Summary:$Summary -Container:$Container -SDKName:$SDKName
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
Get the security descriptor from an object.
.DESCRIPTION
This cmdlet gets the security descriptor from an object with specified list of security information.
.PARAMETER Object
The object to get the security descriptor from.
.PARAMETER SecurityInformation
The security information to get from the object.
.PARAMETER AsSddl
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
.PARAMETER NamedPipeDefault
 Specify to get the default security descriptor for a named pipe.
.INPUTS
NtCoreLib.NtObject[]
.OUTPUTS
NtCoreLib.Security.Authorization.SecurityDescriptor
string
.EXAMPLE
Get-NtSecurityDescriptor $obj
Get the security descriptor with default security information.
.EXAMPLE
Get-NtSecurityDescriptor $obj Dacl,Owner,Group
Get the security descriptor with DACL, OWNER and GROUP values.
.EXAMPLE
Get-NtSecurityDescriptor $obj Dacl -AsSddl
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
.EXAMPLE
Get-NtSecurityDescriptor -NamedPipeDefault
Get the default security descriptor for a named pipe.
.EXAMPLE
Get-NtSecurityDescriptor -ProcessId 1234
Get the security descriptor for Process ID 1234.
.EXAMPLE
Get-NtSecurityDescriptor -ThreadId 5678
Get the security descriptor for Thread ID 5678.
#>
function Get-NtSecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName = "FromObject")]
    param (
        [parameter(Mandatory, Position = 0, ValueFromPipeline, ParameterSetName = "FromObject")]
        [NtCoreLib.Security.Authorization.INtObjectSecurity]$Object,
        [parameter(Position = 1, ParameterSetName = "FromObject")]
        [parameter(Position = 1, ParameterSetName = "FromPath")]
        [parameter(ParameterSetName = "FromPid")]
        [parameter(ParameterSetName = "FromTid")]
        [NtCoreLib.Security.Authorization.SecurityInformation]$SecurityInformation = "AllBasic",
        [parameter(Mandatory, ParameterSetName = "FromProcess")]
        [NtCoreLib.NtProcess]$Process,
        [parameter(Mandatory, ParameterSetName = "FromProcess")]
        [int64]$Address,
        [parameter(Mandatory, Position = 0, ParameterSetName = "FromPath")]
        [string]$Path,
        [parameter(ParameterSetName = "FromPath")]
        [string]$TypeName,
        [parameter(ParameterSetName = "FromPath")]
        [NtCoreLib.NtObject]$Root,
        [parameter(Mandatory, ParameterSetName = "FromPid")]
        [alias("pid")]
        [int]$ProcessId,
        [parameter(Mandatory, ParameterSetName = "FromTid")]
        [alias("tid")]
        [int]$ThreadId,
        [parameter(Mandatory, ParameterSetName = "FromNp")]
        [switch]$NamedPipeDefault,
        [alias("ToSddl")]
        [switch]$AsSddl
    )
    PROCESS {
        $sd = switch ($PsCmdlet.ParameterSetName) {
            "FromObject" {
                $Object.GetSecurityDescriptor($SecurityInformation)
            }
            "FromProcess" {
                [NtCoreLib.Security.Authorization.SecurityDescriptor]::new($Process, [IntPtr]::new($Address))
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
            "FromNp" {
                $dacl = [NtCoreLib.NtNamedPipeFile]::GetDefaultNamedPipeAcl();
                New-NtSecurityDescriptor -Dacl $dacl -Type File
            }
        }
        if ($AsSddl) {
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
NtCoreLib.NtObject[]
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
        [NtCoreLib.Security.Authorization.INtObjectSecurity]$Object,
        [parameter(Mandatory, Position = 0, ParameterSetName = "ToPath")]
        [string]$Path,
        [parameter(ParameterSetName = "ToPath")]
        [NtCoreLib.NtObject]$Root,
        [parameter(Mandatory, Position = 1)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [parameter(Mandatory, Position = 2)]
        [NtCoreLib.Security.Authorization.SecurityInformation]$SecurityInformation,
        [parameter(ParameterSetName = "ToPath")]
        [string]$TypeName

    )
    PROCESS {
        switch ($PsCmdlet.ParameterSetName) {
            "ToObject" {
                $Object.SetSecurityDescriptor($SecurityDescriptor, $SecurityInformation)
            }
            "ToPath" {
                $access = Get-NtAccessMask -SecurityInformation $SecurityInformation -ToGenericAccess -SetSecurity
                Use-NtObject($obj = Get-NtObject -Path $Path -Root $Root -TypeName $TypeName -Access $access) {
                    $obj.SetSecurityDescriptor($SecurityDescriptor, $SecurityInformation)
                }
            }
        }
    }
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
NtCoreLib.Security.Authorization.SecurityDescriptor
#>
function Copy-NtSecurityDescriptor {
    Param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
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
NtCoreLib.Security.Authorization.SecurityDescriptor
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
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, Mandatory, ParameterSetName = "ModifySd")]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$NewSecurityDescriptor,
        [Parameter(Position = 2, Mandatory, ParameterSetName = "ModifySd")]
        [NtCoreLib.Security.Authorization.SecurityInformation]$SecurityInformation,
        [Parameter(ParameterSetName = "ModifySd")]
        [NtCoreLib.NtToken]$Token,
        [Parameter(ParameterSetName = "ModifySd")]
        [NtCoreLib.Security.Authorization.SecurityAutoInheritFlags]$Flags = 0,
        [Parameter(ParameterSetName = "ModifySd")]
        [Parameter(ParameterSetName = "ToAutoInherit")]
        [Parameter(ParameterSetName = "MapGenericSd")]
        [Parameter(ParameterSetName = "UnmapGenericSd")]
        [NtCoreLib.NtType]$Type,
        [Parameter(ParameterSetName = "CanonicalizeSd")]
        [switch]$CanonicalizeDacl,
        [Parameter(ParameterSetName = "CanonicalizeSd")]
        [switch]$CanonicalizeSacl,
        [Parameter(Mandatory, ParameterSetName = "MapGenericSd")]
        [switch]$MapGeneric,
        [Parameter(Mandatory, ParameterSetName = "UnmapGenericSd")]
        [switch]$UnmapGeneric,
        [Parameter(Mandatory, ParameterSetName = "ToAutoInherit")]
        [switch]$ConvertToAutoInherit,
        [Parameter(ParameterSetName = "ToAutoInherit")]
        [switch]$Container,
        [Parameter(ParameterSetName = "ToAutoInherit")]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$Parent,
        [Parameter(ParameterSetName = "ToAutoInherit")]
        [Nullable[Guid]]$ObjectType = $null,
        [Parameter(ParameterSetName = "StandardizeSd")]
        [switch]$Standardize,
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
    elseif ($PsCmdlet.ParameterSetName -eq "UnmapGenericSd") {
        $SecurityDescriptor.UnmapGenericAccess($Type)
    }
    elseif ($PsCmdlet.ParameterSetName -eq "ToAutoInherit") {
        $SecurityDescriptor.ConvertToAutoInherit($Parent,
            $ObjectType, $Container, $Type.GenericMapping)
    }
    elseif ($PSCmdlet.ParameterSetName -eq "StandardizeSd") {
        $SecurityDescriptor.Standardize()
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
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, Mandatory, ParameterSetName = "FromSid")]
        [NtCoreLib.Security.Authorization.Sid]$Owner,
        [Parameter(Mandatory, ParameterSetName = "FromName")]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName = "FromKnownSid")]
        [NtCoreLib.Security.Authorization.KnownSidValue]$KnownSid,
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

    $SecurityDescriptor.Owner = [NtCoreLib.Security.Authorization.SecurityDescriptorSid]::new($sid, $Defaulted)
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
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
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
NtCoreLib.Security.Authorization.SecurityDescriptorSid
#>
function Get-NtSecurityDescriptorOwner {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
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
NtCoreLib.Security.Authorization.SecurityDescriptorSid
#>
function Get-NtSecurityDescriptorGroup {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
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
NtCoreLib.Security.Authorization.Acl
#>
function Get-NtSecurityDescriptorDacl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
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
NtCoreLib.Security.Authorization.Acl
#>
function Get-NtSecurityDescriptorSacl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
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
NtCoreLib.Security.Authorization.SecurityDescriptorControl
#>
function Get-NtSecurityDescriptorControl {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
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
NtCoreLib.Security.Authorization.Sid or NtCoreLib.TokenIntegrityLevel
#>
function Get-NtSecurityDescriptorIntegrityLevel {
    [CmdletBinding(DefaultParameterSetName = "ToIL")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
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
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptorControl]$Control,
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
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptorControl]$Control,
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
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, Mandatory)]
        [NtCoreLib.Security.Authorization.SecurityDescriptorControl]$Control,
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
NtCoreLib.Security.Authorization.Acl
#>
function New-NtAcl {
    [CmdletBinding(DefaultParameterSetName = "FromAce")]
    Param(
        [Parameter(Mandatory, ParameterSetName = "NullAcl")]
        [switch]$NullAcl,
        [Parameter(ParameterSetName = "FromAce")]
        [NtCoreLib.Security.Authorization.Ace[]]$Ace,
        [switch]$AutoInheritReq,
        [switch]$AutoInherited,
        [switch]$Protected,
        [switch]$Defaulted
    )

    $acl = New-Object NtCoreLib.Security.Authorization.Acl
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
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Mandatory, ParameterSetName = "NullAcl")]
        [switch]$NullAcl,
        [Parameter(ParameterSetName = "FromAce")]
        [NtCoreLib.Security.Authorization.Ace[]]$Ace,
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
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Mandatory, ParameterSetName = "NullAcl")]
        [switch]$NullAcl,
        [Parameter(ParameterSetName = "FromAce")]
        [NtCoreLib.Security.Authorization.Ace[]]$Ace,
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
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
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
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
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
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
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
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
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
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
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
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, Mandatory, ParameterSetName = "FromSid")]
        [NtCoreLib.Security.Authorization.Sid]$Group,
        [Parameter(Mandatory, ParameterSetName = "FromName")]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName = "FromKnownSid")]
        [NtCoreLib.Security.Authorization.KnownSidValue]$KnownSid,
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

    $SecurityDescriptor.Group = [NtCoreLib.Security.Authorization.SecurityDescriptorSid]::new($sid, $Defaulted)
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
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
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
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor
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
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Position = 1, Mandatory, ParameterSetName = "FromSid")]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [Parameter(Position = 1, Mandatory, ParameterSetName = "FromLevel")]
        [NtCoreLib.TokenIntegrityLevel]$IntegrityLevel,
        [Parameter(ParameterSetName = "FromLevel")]
        [Parameter(ParameterSetName = "FromSid")]
        [NtCoreLib.Security.Authorization.AceFlags]$Flags = 0,
        [Parameter(ParameterSetName = "FromLevel")]
        [Parameter(ParameterSetName = "FromSid")]
        [NtCoreLib.Security.Authorization.MandatoryLabelPolicy]$Policy = "NoWriteUp"
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
Converts an ACE condition string expression to a byte array or a parsed object.
.DESCRIPTION
This cmdlet gets a byte array or a parsed object for an ACE conditional string expression.
.PARAMETER Condition
The condition string expression.
.PARAMETER AsObject
Specify to the return the conditional expression as a parsed object.
.INPUTS
None
.OUTPUTS
byte[]
NtCoreLib.Security.Authorization.ConditionalExpression.ConditionalExpression
.EXAMPLE
ConvertFrom-NtAceCondition -Condition 'WIN://TokenId == "TEST"'
Gets the data for the condition expression 'WIN://TokenId == "TEST"'
.EXAMPLE
ConvertFrom-NtAceCondition -Condition 'WIN://TokenId == "TEST"' -AsObject
Gets the object for the condition expression 'WIN://TokenId == "TEST"'
#>
function ConvertFrom-NtAceCondition {
    [CmdletBinding(DefaultParameterSetName = "AsBytes")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Condition,
        [Parameter(Mandatory, ParameterSetName="AsObject")]
        [switch]$AsObject
    )

    if ($AsObject) {
        [NtCoreLib.Security.Authorization.ConditionalExpression.ConditionalExpression]::Parse($Condition)
    } else {
        [NtCoreLib.Security.NtSecurity]::StringToConditionalAce($Condition)
    }
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

    [NtCoreLib.Security.NtSecurity]::ConditionalAceToString($ConditionData)
}

<#
.SYNOPSIS
Converts a security descriptor to a self-relative byte array or base64 string.
.DESCRIPTION
This cmdlet converts a security descriptor to a self-relative byte array or a base64 string.
.PARAMETER SecurityDescriptor
The security descriptor to convert.
.PARAMETER AsBase64
Converts the self-relative SD to base64 string.
.INPUTS
None
.OUTPUTS
byte[]
.EXAMPLE
ConvertFrom-NtSecurityDescriptor -SecurityDescriptor "O:SYG:SYD:(A;;GA;;;WD)"
Converts security descriptor to byte array.
.EXAMPLE
ConvertFrom-NtSecurityDescriptor -SecurityDescriptor "O:SYG:SYD:(A;;GA;;;WD)" -AsBase64
Converts security descriptor to a base64 string.
.EXAMPLE
ConvertFrom-NtSecurityDescriptor -SecurityDescriptor "O:SYG:SYD:(A;;GA;;;WD)" -AsBase64 -InsertLineBreaks
Converts security descriptor to a base64 string with line breaks.
#>
function ConvertFrom-NtSecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName = "ToBytes")]
    Param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [Parameter(Mandatory, ParameterSetName = "ToBase64")]
        [alias("Base64")]
        [switch]$AsBase64,
        [Parameter(ParameterSetName = "ToBase64")]
        [switch]$InsertLineBreaks
    )

    PROCESS {
        if ($AsBase64) {
            $SecurityDescriptor.ToBase64($InsertLineBreaks) | Write-Output
        }
        else {
            $SecurityDescriptor.ToByteArray() | Write-Output -NoEnumerate
        }
    }
}

<#
.SYNOPSIS
Converts a SID to a byte array.
.DESCRIPTION
This cmdlet converts a SID to a byte array.
.PARAMETER Sid
The SID to convert.
.INPUTS
None
.OUTPUTS
byte[]
.EXAMPLE
ConvertFrom-NtSid -Sid "S-1-1-0"
Converts SID to byte array.
#>
function ConvertFrom-NtSid {
    [CmdletBinding(DefaultParameterSetName = "ToBytes")]
    Param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [NtCoreLib.Security.Authorization.Sid]$Sid
    )

    PROCESS {
        $Sid.ToArray() | Write-Output -NoEnumerate
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
NtCoreLib.Security.Authorization.Sid[]
.OUTPUTS
NtCoreLib.Security.Token.UserGroup[]
.EXAMPLE
New-NtUserGroup -Sid "WD" -Attribute Enabled
Creates a new UserGroup with the World SID and the Enabled Flag.
#>
function New-NtUserGroup {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [NtCoreLib.Security.Authorization.Sid[]]$Sid,
        [NtCoreLib.GroupAttributes]$Attribute = 0
    )

    PROCESS {
        foreach ($s in $Sid) {
            New-Object NtCoreLib.Security.Token.UserGroup -ArgumentList $s, $Attribute
        }
    }
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
.PARAMETER SchemaObject
Specify to create from a schema object such as a schema class or extended right.
.INPUTS
None
.OUTPUTS
NtCoreLib.Utilities.Security.Authorization.ObjectTypeTree
.EXAMPLE
$tree = New-ObjectTypeTree "bf967a86-0de6-11d0-a285-00aa003049e2"
Creates a new Object Type tree with the root type as 'bf967a86-0de6-11d0-a285-00aa003049e2'.
.EXAMPLE
$tree = New-ObjectTypeTree "bf967a86-0de6-11d0-a285-00aa003049e2" -Nodes $children
Creates a new Object Type tree with the root type as 'bf967a86-0de6-11d0-a285-00aa003049e2' with a list of children.
#>
function New-ObjectTypeTree {
    [CmdletBinding(DefaultParameterSetName="FromGuid")]
    Param(
        [Parameter(Position = 0, Mandatory, ParameterSetName = "FromGuid")]
        [guid]$ObjectType,
        [Parameter(ParameterSetName = "FromGuid")]
        [NtCoreLib.Utilities.Security.Authorization.ObjectTypeTree[]]$Nodes,
        [Parameter(ParameterSetName = "FromGuid")]
        [string]$Name = "",
        [parameter(Mandatory, ParameterSetName = "FromSchemaObject", Position = 0)]
        [NtCoreLib.Win32.DirectoryService.IDirectoryServiceObjectTree]$SchemaObject
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromGuid" {
            $tree = New-Object NtCoreLib.Utilities.Security.Authorization.ObjectTypeTree -ArgumentList $ObjectType
            if ($null -ne $Nodes) {
                $tree.AddNodeRange($Nodes)
            }
            $tree.Name = $Name
            $tree
        }
        "FromSchemaObject" {
            ConvertTo-ObjectTypeTree -SchemaObject $SchemaObject
        }
    }
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
.PARAMETER SchemaObject
Specify to add a schema object such as a schema class or extended right.
.INPUTS
None
.OUTPUTS
NtCoreLib.Utilities.Security.Authorization.ObjectTypeTree
.EXAMPLE
Add-ObjectTypeTree $tree "bf967a86-0de6-11d0-a285-00aa003049e2"
Adds a new Object Type tree with the root type as 'bf967a86-0de6-11d0-a285-00aa003049e2'.
.EXAMPLE
Add-ObjectTypeTree $tree "bf967a86-0de6-11d0-a285-00aa003049e2" -Name "Property A"
Adds a new Object Type tree with the root type as 'bf967a86-0de6-11d0-a285-00aa003049e2'.
.EXAMPLE
Add-ObjectTypeTree $tree $obj
Adds a new Object Type tree based on a directory object.
#>
function Add-ObjectTypeTree {
    [CmdletBinding(DefaultParameterSetName="FromGuid")]
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Utilities.Security.Authorization.ObjectTypeTree]$Tree,
        [Parameter(Position = 1, Mandatory, ParameterSetName = "FromGuid")]
        [guid]$ObjectType,
        [Parameter(ParameterSetName = "FromGuid")]
        [string]$Name = "",
        [parameter(Mandatory, ParameterSetName = "FromSchemaObject", Position = 1, ValueFromPipeline)]
        [NtCoreLib.Win32.DirectoryService.IDirectoryServiceObjectTree]$SchemaObject,
        [switch]$PassThru
    )

    PROCESS {
        $result = switch($PSCmdlet.ParameterSetName) {
            "FromGuid" {
                $r = $Tree.AddNode($ObjectType)
                $r.Name = $Name
                $r
            }
            "FromSchemaObject" {
                $r = ConvertTo-ObjectTypeTree -SchemaObject $SchemaObject
                $Tree.AddNode($r)
                $r
            }
        }
        if ($PassThru) {
            Write-Output $result
        }
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
        [NtCoreLib.Utilities.Security.Authorization.ObjectTypeTree]$Tree
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
        [NtCoreLib.Utilities.Security.Authorization.ObjectTypeTree]$Tree,
        [Parameter(Position = 1, Mandatory)]
        [NtCoreLib.Security.Authorization.AccessMask]$Access
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
        [NtCoreLib.Utilities.Security.Authorization.ObjectTypeTree]$Tree,
        [Parameter(Position = 1, Mandatory)]
        [NtCoreLib.Security.Authorization.AccessMask]$Access
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
NtCoreLib.Utilities.Security.Authorization.ObjectTypeTree
.EXAMPLE
Select-ObjectTypeTree $tree "bf967a86-0de6-11d0-a285-00aa003049e2"
Selects an Object Type tree with the type of 'bf967a86-0de6-11d0-a285-00aa003049e2'.
#>
function Select-ObjectTypeTree {
    Param(
        [Parameter(Position = 0, Mandatory)]
        [NtCoreLib.Utilities.Security.Authorization.ObjectTypeTree]$Tree,
        [Parameter(Position = 1, Mandatory)]
        [guid]$ObjectType
    )
    
    $Tree.Find($ObjectType) | Write-Output
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
.PARAMETER SchemaObject
Specify an object convertable to the tree such as a schema object or extended right.
.INPUTS
None
.OUTPUTS
NtCoreLib.Utilities.Security.Authorization.ObjectTypeTree
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
        [parameter(Mandatory, ParameterSetName = "FromSchemaObject", ValueFromPipeline, Position = 0)]
        [NtCoreLib.Win32.DirectoryService.IDirectoryServiceObjectTree]$SchemaObject
    )

    PROCESS {
        $tree_obj = switch($PSCmdlet.ParameterSetName) {
            "FromName" {
               Get-DsObjectSchemaClass -Domain $Domain -Name $DistinguishedName
            }
            "FromObject" {
                Get-DsObjectSchemaClass -Object $Object
            }
            "FromSchemaObject" {
                $SchemaObject
            }
        }
        $tree_obj.ToObjectTypeTree()
    }
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
NtCoreLib.Security.Authorization.Policy.CentralAccessPolicy
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
        [NtCoreLib.Security.Authorization.Sid]$CapId,
        [switch]$FromLsa
    )
    $policy = if ($FromLsa) {
        [NtCoreLib.Security.Authorization.Policy.CentralAccessPolicy]::ParseFromLsa()
    }
    else {
        [NtCoreLib.Security.Authorization.Policy.CentralAccessPolicy]::ParseFromRegistry()
    }
    if ($null -eq $CapId) {
        $policy | Write-Output
    } else {
        $policy | Where-Object CapId -eq $CapId | Select-Object -First 1 | Write-Output
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
NtCoreLib.Win32.Security.Audit.AuditCategory
NtCoreLib.Win32.Security.Audit.AuditSubCategory
NtCoreLib.Win32.Security.Audit.AuditPerUserCategory
NtCoreLib.Win32.Security.Audit.AuditPerUserSubCategory
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
        [NtCoreLib.Win32.Security.Audit.AuditPolicyEventType[]]$Category,
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
        [NtCoreLib.Security.Authorization.Sid]$User
    )

    $cats = switch ($PSCmdlet.ParameterSetName) {
        "All" {
            if ($null -ne $User) {
                [NtCoreLib.Win32.Security.Audit.AuditSecurityUtils]::GetPerUserCategories($User)
            }
            elseif ($AllUser) {
                [NtCoreLib.Win32.Security.Audit.AuditSecurityUtils]::GetPerUserCategories()
            }
            else {
                [NtCoreLib.Win32.Security.Audit.AuditSecurityUtils]::GetCategories()
            }
        }
        "FromCategory" {
            $ret = @()
            foreach($cat in $Category) {
                if ($null -ne $User) {
                    $ret += [NtCoreLib.Win32.Security.Audit.AuditSecurityUtils]::GetPerUserCategory($User, $cat)
                } else {
                    $ret += [NtCoreLib.Win32.Security.Audit.AuditSecurityUtils]::GetCategory($cat)
                }
            }
            $ret
        }
        "FromCategoryGuid" {
            $ret = @()
            foreach($cat in $CategoryGuid) {
                if ($null -ne $User) {
                    $ret += [NtCoreLib.Win32.Security.Audit.AuditSecurityUtils]::GetPerUserCategory($User, $cat)
                } else {
                    $ret += [NtCoreLib.Win32.Security.Audit.AuditSecurityUtils]::GetCategory($cat)
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
NtCoreLib.Win32.Security.Audit.AuditSubCategory
NtCoreLib.Win32.Security.Audit.AuditPerUserSubCategory
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
        [NtCoreLib.Win32.Security.Audit.AuditPolicyEventType[]]$Category,
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
        [NtCoreLib.Win32.Security.Audit.AuditPolicyFlags]$Policy,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromCategoryTypeUser")]
        [parameter(Mandatory, Position = 1, ParameterSetName="FromCategoryGuidUser")]
        [parameter(Mandatory, Position = 1, ParameterSetName="FromSubCategoryNameUser")]
        [parameter(Mandatory, Position = 1, ParameterSetName="FromSubCategoryGuidUser")]
        [NtCoreLib.Win32.Security.Audit.AuditPerUserPolicyFlags]$UserPolicy,
        [parameter(Mandatory, ParameterSetName="FromCategoryTypeUser")]
        [parameter(Mandatory, ParameterSetName="FromCategoryGuidUser")]
        [parameter(Mandatory, ParameterSetName="FromSubCategoryNameUser")]
        [parameter(Mandatory, ParameterSetName="FromSubCategoryGuidUser")]
        [NtCoreLib.Security.Authorization.Sid]$User,
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
NtCoreLib.Security.Authorization.SecurityDescriptor
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
        [NtCoreLib.Win32.Security.Audit.AuditGlobalSaclType]$GlobalSacl
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromSecurityDescriptor" {
            [NtCoreLib.Win32.Security.Audit.AuditSecurityUtils]::QuerySecurity() | Write-Output
        }
        "FromGlobalSacl" {
            [NtCoreLib.Win32.Security.Audit.AuditSecurityUtils]::QueryGlobalSacl($GlobalSacl) | Write-Output
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
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$SecurityDescriptor,
        [parameter(Mandatory, Position = 1, ParameterSetName = "FromGlobalSacl")]
        [NtCoreLib.Win32.Security.Audit.AuditGlobalSaclType]$GlobalSacl
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromSecurityDescriptor" {
            if ($PSCmdlet.ShouldProcess("$SecurityDescriptor", "Set Audit SD")) {
                [NtCoreLib.Win32.Security.Audit.AuditSecurityUtils]::SetSecurity("Dacl", $SecurityDescriptor)
            }
        }
        "FromGlobalSacl" {
            if ($PSCmdlet.ShouldProcess("$SecurityDescriptor", "Set $GlobalSacl SACL")) {
                [NtCoreLib.Win32.Security.Audit.AuditSecurityUtils]::SetGlobalSacl($GlobalSacl, $SecurityDescriptor)
            }
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
NtCoreLib.Win32.Security.Policy.AccountRight
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
        [NtCoreLib.Win32.Security.Policy.AccountRightType]$Type = "All",
        [parameter(Mandatory, ParameterSetName = "FromSid")]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [parameter(Mandatory, ParameterSetName = "FromKnownSid")]
        [NtCoreLib.Security.Authorization.KnownSidValue]$KnownSid,
        [parameter(Mandatory, ParameterSetName = "FromName")]
        [string]$Name
    )

    switch($PSCmdlet.ParameterSetName) {
        "All" {
            [NtCoreLib.Win32.Security.Win32Security]::GetAccountRights($Type) | Write-Output
        }
        "FromSid" {
            [NtCoreLib.Win32.Security.Win32Security]::GetAccountRights($Sid) | Write-Output
        }
        "FromKnownSid" {
            [NtCoreLib.Win32.Security.Win32Security]::GetAccountRights((Get-NtSid -KnownSid $KnownSid)) | Write-Output
        }
        "FromName" {
            [NtCoreLib.Win32.Security.Win32Security]::GetAccountRights((Get-NtSid -Name $Name)) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Add account rights for current system.
.DESCRIPTION
This cmdlet adds account rights for the current system to a SID.
.PARAMETER Sid
Specify a SID to add the account right for.
.PARAMETER Privilege
Specify the privileges to add.
.PARAMETER Name
Specify the list of account right names to add.
.PARAMETER LogonType
Specify the list of logon types to add.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Add-NtAccountRight -Sid WD -Privilege SeAssignPrimaryTokenPrivilege
Add everyone group to SeAssignPrimaryTokenPrivilege
#>
function Add-NtAccountRight {
    [CmdletBinding(DefaultParameterSetName = "FromPrivs")]
    param (
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [parameter(Mandatory, ParameterSetName = "FromPrivs")]
        [NtCoreLib.Security.Token.TokenPrivilegeValue[]]$Privilege,
        [parameter(Mandatory, ParameterSetName = "FromString")]
        [string[]]$Name,
        [parameter(Mandatory, ParameterSetName = "FromLogonType")]
        [NtCoreLib.Win32.Security.Policy.AccountRightLogonType[]]$LogonType
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromString" {
            [NtCoreLib.Win32.Security.Win32Security]::AddAccountRights($Sid, $Name)
        }
        "FromPrivs" {
            [NtCoreLib.Win32.Security.Win32Security]::AddAccountRights($Sid, $Privilege)
        }
        "FromLogonType" {
            [NtCoreLib.Win32.Security.Win32Security]::AddAccountRights($Sid, $LogonType)
        }
    }
}

<#
.SYNOPSIS
Remove account rights for current system.
.DESCRIPTION
This cmdlet removes account rights for the current system from a SID.
.PARAMETER Sid
Specify a SID to remove the account right for.
.PARAMETER Privilege
Specify the privileges to remove.
.PARAMETER Name
Specify the list of account right names to remove.
.PARAMETER LogonType
Specify the list of logon types to remove.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Remove-NtAccountRight -Sid WD -Privilege SeAssignPrimaryTokenPrivilege
Remove everyone group from SeAssignPrimaryTokenPrivilege
#>
function Remove-NtAccountRight {
    [CmdletBinding(DefaultParameterSetName = "FromPrivs")]
    param (
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [parameter(Mandatory, ParameterSetName = "FromPrivs")]
        [NtCoreLib.Security.Token.TokenPrivilegeValue[]]$Privilege,
        [parameter(Mandatory, ParameterSetName = "FromString")]
        [string[]]$Name,
        [parameter(Mandatory, ParameterSetName = "FromLogonType")]
        [NtCoreLib.Win32.Security.Policy.AccountRightLogonType[]]$LogonType
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromString" {
            [NtCoreLib.Win32.Security.Win32Security]::RemoveAccountRights($Sid, $Name)
        }
        "FromPrivs" {
            [NtCoreLib.Win32.Security.Win32Security]::RemoveAccountRights($Sid, $Privilege)
        }
        "FromLogonType" {
            [NtCoreLib.Win32.Security.Win32Security]::RemoveAccountRights($Sid, $LogonType)
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
NtCoreLib.Security.Authorization.Sid
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
        [NtCoreLib.Security.Token.TokenPrivilegeValue]$Privilege,
        [parameter(Mandatory, ParameterSetName = "FromLogon")]
        [NtCoreLib.Win32.Security.Policy.AccountRightLogonType]$Logon
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromPrivilege" {
            [NtCoreLib.Win32.Security.Win32Security]::GetAccountRightSids($Privilege) | Write-Output
        }
        "FromLogon" {
            [NtCoreLib.Win32.Security.Win32Security]::GetAccountRightSids($Logon) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Add a SID to name mapping.
.DESCRIPTION
This cmdlet adds a SID to name mapping. You can also add the name to LSASS if you have SeTcbPrivilege
and the SID meets specific requirements.
.PARAMETER Sid
Specify the SID to add.
.PARAMETER Domain
Specify the domain name to add. When adding a cache this is optional. For register this is required.
.PARAMETER Name
Specify the name to add. For register this is optional.
.PARAMETER NameUse
Specify the name to use type.
.PARAMETER Register
Register SID name with LSASS.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Add-NtSidName -Sid S-1-2-3-4-5 -Domain ABC -User XYZ
Add a SID name.
.EXAMPLE
Add-NtSidName -Sid S-1-5-101-0 -Domain ABC -User XYZ -Register
Add a SID name and register with LSASS.
#>
function Add-NtSidName {
    [CmdletBinding(DefaultParameterSetName="FromName")]
    param (
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromName")]
        [parameter(Position = 2, ParameterSetName="RegisterSid")]
        [string]$Name,
        [parameter(Position = 2, ParameterSetName="FromName")]
        [parameter(Mandatory, Position = 1, ParameterSetName="RegisterSid")]
        [string]$Domain,
        [parameter(Position = 3, ParameterSetName="FromName")]
        [NtCoreLib.Security.Authorization.SidNameUse]$NameUse = "Group",
        [parameter(Mandatory, ParameterSetName="RegisterSid")]
        [switch]$Register
    )

    if ($Register) {
        [NtCoreLib.Win32.Security.Win32Security]::AddSidNameMapping($Domain, $Name, $Sid)
    } else {
        [NtCoreLib.Security.NtSecurity]::AddSidName($Sid, $Domain, $Name, $NameUse)
    }
}

<#
.SYNOPSIS
Add a SID to name mapping.
.DESCRIPTION
This cmdlet adds a SID to name mapping. You can also add the name to LSASS if you have SeTcbPrivilege
and the SID meets specific requirements.
.PARAMETER Sid
Specify an API set name to lookup.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Remove-NtSidName -Sid S-1-2-3-4-5
Remove a SID name.
.EXAMPLE
Remove-NtSidName -Sid S-1-5-101-0 -Unregister
Remove a SID name and unregister with LSASS.
#>
function Remove-NtSidName {
    [CmdletBinding()]
    param (
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [switch]$Unregister
    )

    if ($Unregister) {
        [NtCoreLib.Win32.Security.Win32Security]::RemoveSidNameMapping($Sid)
    }
    [NtCoreLib.Security.NtSecurity]::RemoveSidName($Sid)
}

<#
.SYNOPSIS
Clear the SID to name cache.
.DESCRIPTION
This cmdlet clears the SID to name cache.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Clear-NtSidName
Clears the SID to name cache.
#>
function Clear-NtSidName {
    [NtCoreLib.Security.NtSecurity]::ClearSidNameCache()
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
.INPUTS
NtCoreLib.Security.Authorization.Sid[]
.OUTPUTS
NtCoreLib.Security.Authorization.SidName
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
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [switch]$BypassCache
    )

    PROCESS {
        $Sid.GetName($BypassCache)
    }
}

<#
.SYNOPSIS
Test properties of a SID.
.DESCRIPTION
This cmdlet tests the SID for various different properties such as whether it's a capability SID.
.PARAMETER Sid
The SID to test.
.PARAMETER Integrity
Specify to check if the SID is an integrity SID.
.PARAMETER Capability
Specify to check if the SID is a capability SID.
.PARAMETER CapabilityGroup
Specify to check if the SID is a capability group SID.
.PARAMETER Service
Specify to check if the SID is a service SID.
.PARAMETER LogonSession
Specify to check if the SID is a logon session SID.
.PARAMETER ProcessTrust
Specify to check if the SID is a process trust SID.
.PARAMETER Domain
Specify to check if the SID is a domain SID.
.PARAMETER LocalDomain
Specify to check if the SID is the local domain SID.
.INPUTS
NtCoreLib.Security.Authorization.Sid[]
.OUTPUTS
bool
.EXAMPLE
Test-NtSid "S-1-16-12288" -IsIntegrity
Checks if the SID is an integrity SID.
#>
function Test-NtSid {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [NtCoreLib.Security.Authorization.Sid]$Sid,
        [parameter(Mandatory, ParameterSetName="Integrity")]
        [switch]$Integrity,
        [parameter(Mandatory, ParameterSetName="Capability")]
        [switch]$Capability,
        [parameter(Mandatory, ParameterSetName="CapabilityGroup")]
        [switch]$CapabilityGroup,
        [parameter(Mandatory, ParameterSetName="Service")]
        [switch]$Service,
        [parameter(Mandatory, ParameterSetName="LogonSession")]
        [switch]$LogonSession,
        [parameter(Mandatory, ParameterSetName="ProcessTrust")]
        [switch]$ProcessTrust,
        [parameter(Mandatory, ParameterSetName="Domain")]
        [switch]$Domain,
        [parameter(Mandatory, ParameterSetName="LocalDomain")]
        [switch]$LocalDomain
    )

    PROCESS {
        switch($PSCmdlet.ParameterSetName) {
            "Integrity" {
                [NtCoreLib.Security.NtSecurity]::IsIntegritySid($Sid)
            }
            "Capability" {
                [NtCoreLib.Security.NtSecurity]::IsCapabilitySid($Sid)
            }
            "CapabilityGroup" {
                [NtCoreLib.Security.NtSecurity]::IsCapabilityGroupSid($Sid)
            }
            "Service" {
                [NtCoreLib.Security.NtSecurity]::IsServiceSid($Sid)
            }
            "LogonSession" {
                [NtCoreLib.Security.NtSecurity]::IsLogonSessionSid($Sid)
            }
            "ProcessTrust" {
                [NtCoreLib.Security.NtSecurity]::IsProcessTrustSid($Sid)
            }
            "Domain" {
                [NtCoreLib.Security.NtSecurity]::IsDomainSid($Sid)
            }
            "LocalDomain" {
                [NtCoreLib.Security.NtSecurity]::IsLocalDomainSid($Sid)
            }
        }
    }
}
