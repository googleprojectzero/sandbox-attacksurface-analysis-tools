#  Copyright 2021 Google LLC. All Rights Reserved.
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

$layer_completer = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    [NtCoreLib.Net.Firewall.FirewallUtils]::GetKnownLayerNames() | Where-Object { $_ -like "$wordToComplete*" }
}

$sublayer_completer = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    [NtCoreLib.Net.Firewall.FirewallUtils]::GetKnownSubLayerNames() | Where-Object { $_ -like "$wordToComplete*" }
}

$callout_completer = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    [NtCoreLib.Net.Firewall.FirewallUtils]::GetKnownCalloutNames() | Where-Object { $_ -like "$wordToComplete*" }
}

$Script:GlobalFwEngine = $null

function Get-FwEngineSingleton {
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine
    )

    if ($null -ne $Engine) {
        return $Engine
    }

    if ($Script:GlobalFwEngine -eq $null) {
        $Script:GlobalFwEngine = Get-FwEngine
    }
    return $Script:GlobalFwEngine
}

<#
.SYNOPSIS
Get a firewall engine instance.
.DESCRIPTION
This cmdlet gets an instance of the firewall engine.
.PARAMETER ServerName
The name of the server running the firewall service.
.PARAMETER Credentials
The user credentials for the RPC connection.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallEngine
.EXAMPLE
Get-FwEngine
Get local firewall engine.
.EXAMPLE
Get-FwEngine -ServerName "SERVER1"
Get firewall engine on server "SERVER1"
#>
function Get-FwEngine {
    [CmdletBinding()]
    Param(
        [string]$ServerName,
        [NtCoreLib.Win32.Rpc.Transport.RpcAuthenticationType]$AuthnService = "WinNT",
        [NtCoreLib.Win32.Security.Authentication.UserCredentials]$Credentials,
        [switch]$Dynamic
    )

    $session = if ($Dynamic) {
        [NtCoreLib.Net.Firewall.FirewallSession]::new("Dynamic")
    }

    [NtCoreLib.Net.Firewall.FirewallEngine]::Open($ServerName, $AuthnService, $Credentials, $session)
}

<#
.SYNOPSIS
Get a firewall layer.
.DESCRIPTION
This cmdlet gets a firewall layer from an engine. It can return a specific layer or all layers.
.PARAMETER Engine
The firewall engine to query. Optional, if not specified will use a globally set engine.
.PARAMETER Key
Specify the layer key.
.PARAMETER Name
Specify the well-known name of the layer.
.PARAMETER AleLayer
Specify the ALE layer type.
.PARAMETER Id
Specify the ID of the layer.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallLayer[]
.EXAMPLE
Get-FwLayer -Engine $engine
Get all firewall layers.
.EXAMPLE
Get-FwLayer -Engine $engine -Key "c38d57d1-05a7-4c33-904f-7fbceee60e82"
Get firewall layer from key.
.EXAMPLE
Get-FwLayer -Engine $engine -Key "FWPM_LAYER_ALE_AUTH_CONNECT_V4"
Get firewall layer from name.
.EXAMPLE
Get-FwLayer -Engine $engine -Id 1234
Get firewall layer from its ID.
#>
function Get-FwLayer {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromKey")]
        [NtObjectManager.Utils.Firewall.FirewallLayerGuid]$Key,
        [parameter(Mandatory, ParameterSetName="FromAleLayer")]
        [NtCoreLib.Net.Firewall.FirewallAleLayer]$AleLayer,
        [parameter(Mandatory, ParameterSetName="FromId")]
        [int]$Id
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine

        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Engine.EnumerateLayers() | Write-Output
            }
            "FromKey" {
                $Engine.GetLayer($Key.Id)
            }
            "FromAleLayer" {
                $Engine.GetLayer($AleLayer)
            }
            "FromId" {
                $Engine.GetLayer($Id)
            }
        }
    } catch {
        Write-Error $_
    }
}

Register-ArgumentCompleter -CommandName Get-FwLayer -ParameterName Key -ScriptBlock $layer_completer

<#
.SYNOPSIS
Get a firewall sub-layer.
.DESCRIPTION
This cmdlet gets a firewall sub-layer from an engine. It can return a specific sub-layer or all sub-layers.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER Key
Specify the sub-layer key.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallSubLayer[]
.EXAMPLE
Get-FwSubLayer
Get all firewall sub-layers.
.EXAMPLE
Get-FwSubLayer -Key "eebecc03-ced4-4380-819a-2734397b2b74"
Get firewall sub-layer from key.
.EXAMPLE
Get-FwSubLayer -Key "FWPM_SUBLAYER_UNIVERSAL"
Get firewall sub-layer from name.
#>
function Get-FwSubLayer {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, ParameterSetName="FromKey")]
        [NtObjectManager.Utils.Firewall.FirewallSubLayerGuid]$Key
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine

        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Engine.EnumerateSubLayers() | Write-Output
            }
            "FromKey" {
                $Engine.GetSubLayer($Key.Id)
            }
        }
    } catch {
        Write-Error $_
    }
}

Register-ArgumentCompleter -CommandName Get-FwSubLayer -ParameterName Key -ScriptBlock $sublayer_completer

<#
.SYNOPSIS
Get firewall filters.
.DESCRIPTION
This cmdlet gets firewall filters layer from an engine. It can return a filter in a specific layer or for all layers.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER LayerKey
Specify the layer key.
.PARAMETER AleLayer
Specify the ALE layer type.
.PARAMETER Layer
Specify a layer object to query the filters from.
.PARAMETER Key
Specify the filter's key.
.PARAMETER Id
Specify the filter's ID.
.PARAMETER Template
Specify the filter template to enumerate.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallLayer[]
.EXAMPLE
Get-FwFilter -Engine $engine
Get all firewall filters.
.EXAMPLE
Get-FwFilter -Engine $engine -LayerKey "c38d57d1-05a7-4c33-904f-7fbceee60e82"
Get firewall filters from layer key.
.EXAMPLE
Get-FwFilter -Engine $engine -LayerKey "c38d57d1-05a7-4c33-904f-7fbceee60e82" -Sorted
Get firewall filters from layer key in a sorted order.
.EXAMPLE
Get-FwFilter -Engine $engine -Template $template
Get firewall filters based on a template.
#>
function Get-FwFilter {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [parameter(ParameterSetName="All")]
        [parameter(ParameterSetName="FromLayerKey")]
        [parameter(ParameterSetName="FromId")]
        [parameter(ParameterSetName="FromKey")]
        [parameter(ParameterSetName="FromAleLayer")]
        [parameter(ParameterSetName="FromTemplate")]
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromLayerKey")]
        [NtObjectManager.Utils.Firewall.FirewallLayerGuid]$LayerKey,
        [parameter(Mandatory, ParameterSetName="FromAleLayer")]
        [NtCoreLib.Net.Firewall.FirewallAleLayer]$AleLayer,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromLayer", ValueFromPipeline)]
        [NtCoreLib.Net.Firewall.FirewallLayer[]]$Layer,
        [parameter(Mandatory, ParameterSetName="FromId")]
        [uint64]$Id,
        [parameter(Mandatory, ParameterSetName="FromKey")]
        [guid]$Key,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromTemplate")]
        [NtCoreLib.Net.Firewall.FirewallFilterEnumTemplate]$Template,
        [parameter(ParameterSetName="FromLayerKey")]
        [parameter(ParameterSetName="FromAleLayer")]
        [switch]$Sorted,
        [parameter(ParameterSetName="FromLayerKey")]
        [parameter(ParameterSetName="FromAleLayer")]
        [switch]$IncludeDisabled
    )

    PROCESS {
        try {
            $Engine = Get-FwEngineSingleton -Engine $Engine

            switch($PSCmdlet.ParameterSetName) {
                "All" {
                    $Engine.EnumerateFilters() | Write-Output
                }
                "FromLayerKey" {
                    $Template = [NtCoreLib.Net.Firewall.FirewallFilterEnumTemplate]::new($LayerKey.Id)
                }
                "FromAleLayer" {
                    $Template = [NtCoreLib.Net.Firewall.FirewallFilterEnumTemplate]::new($AleLayer)
                }
                "FromLayer" {
                    foreach($l in $Layer) {
                        $l.EnumerateFilters() | Write-Output
                    }
                }
                "FromKey" {
                    $Engine.GetFilter($Key)
                }
                "FromId" {
                    $Engine.GetFilter($Id)
                }
            }
            if ($null -ne $Template) {
                if ($Sorted) {
                    $Template.Flags = $Template.Flags -bor "Sorted"
                }
                if ($IncludeDisabled) {
                    $Template.Flags = $Template.Flags -bor "IncludeDisabled"
                }
                $Engine.EnumerateFilters($Template) | Write-Output
            }
        } catch {
            Write-Error $_
        }
    }
}

Register-ArgumentCompleter -CommandName Get-FwFilter -ParameterName LayerKey -ScriptBlock $layer_completer

<#
.SYNOPSIS
Create a new template for enumerating filters.
.DESCRIPTION
This cmdlet creates a new template for enumerating filters, which can be used with Get-FwFilter.
.PARAMETER LayerKey
Specify the layer key. Can be a GUID or a well known name.
.PARAMETER AleLayer
Specify the ALE layer type.
.PARAMETER Flags
Specify enumeration flags.
.PARAMETER ActionType
Specify enumeration action type.
.PARAMETER Layer
Specify a layer object to query the filters from.
.PARAMETER Condition
Specify one or more conditions to check for when enumerating.
.PARAMETER Token
Specify the user identity for the filter.
.PARAMETER RemoteToken
Specify the remote user identity for the filter.
.PARAMETER Sorted
Specify to sort the filter output.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallFilterEnumTemplate
.EXAMPLE
New-FwFilterTemplate -LayerKey "c38d57d1-05a7-4c33-904f-7fbceee60e82"
Create a template for enumerating firewall filters from layer key.
#>
function New-FwFilterTemplate {
    [CmdletBinding(DefaultParameterSetName="FromLayerKey")]
    param(
        [parameter(Mandatory, ParameterSetName="FromLayerKey")]
        [NtObjectManager.Utils.Firewall.FirewallLayerGuid]$LayerKey,
        [parameter(Mandatory, ParameterSetName="FromAleLayer")]
        [NtCoreLib.Net.Firewall.FirewallAleLayer]$AleLayer,
        [NtCoreLib.Net.Firewall.FirewallFilterEnumFlags]$Flags = "None",
        [NtCoreLib.Net.Firewall.FirewallActionType]$ActionType = "All",
        [NtCoreLib.Net.Firewall.FirewallFilterCondition[]]$Condition,
        [switch]$Sorted
    )

    try {
        $template = switch($PSCmdlet.ParameterSetName) {
            "FromLayerKey" {
                [NtCoreLib.Net.Firewall.FirewallFilterEnumTemplate]::new($LayerKey.Id)
            }
            "FromAleLayer" {
                [NtCoreLib.Net.Firewall.FirewallFilterEnumTemplate]::new($AleLayer)
            }
        }
        if ($Sorted) {
            $Flags = $Flags -bor "Sorted"
        }
        $template.Flags = $Flags
        $template.ActionType = $ActionType
        if ($null -ne $Condition) {
            $template.Conditions.AddRange($Condition)
        }
        $template
    } catch {
        Write-Error $_
    }
}

Register-ArgumentCompleter -CommandName New-FwFilterTemplate -ParameterName LayerKey -ScriptBlock $layer_completer

<#
.SYNOPSIS
Add a firewall filter.
.DESCRIPTION
This cmdlet adds a firewall filter.
.PARAMETER Engine
The firewall engine to add to.
.PARAMETER LayerKey
Specify the layer key. Can be a GUID or a well known name.
.PARAMETER AleLayer
Specify the ALE layer type.
.PARAMETER SubLayerKey
Specify the sub-layer key
.PARAMETER Flags
Specify filters flags.
.PARAMETER ActionType
Specify action type.
.PARAMETER Key
Specify the filter's key.
.PARAMETER Id
Specify the filter's ID.
.PARAMETER Condition
A filter condition builder containing conditions to add.
.INPUTS
None
.OUTPUTS
uint64
#>
function Add-FwFilter {
    [CmdletBinding(DefaultParameterSetName="FromLayerKey")]
    param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 1)]
        [string]$Name,
        [string]$Description = "",
        [parameter(Mandatory, ParameterSetName="FromLayerKey")]
        [NtObjectManager.Utils.Firewall.FirewallLayerGuid]$LayerKey,
        [parameter(Mandatory, ParameterSetName="FromAleLayer")]
        [NtCoreLib.Net.Firewall.FirewallAleLayer]$AleLayer,
        [NtObjectManager.Utils.Firewall.FirewallSubLayerGuid]$SubLayerKey = "FWPM_SUBLAYER_UNIVERSAL",
        [guid]$Key = [guid]::Empty,
        [NtCoreLib.Net.Firewall.FirewallActionType]$ActionType = "Permit",
        [NtCoreLib.Net.Firewall.FirewallConditionBuilder]$Condition,
        [NtCoreLib.Net.Firewall.FirewallValue]$Weight = [NtCoreLib.Net.Firewall.FirewallValue]::Empty,
        [NtCoreLib.Net.Firewall.FirewallFilterFlags]$Flags = 0,
        [guid]$ProviderKey = [guid]::Empty
    )

    try {
        $builder = [NtCoreLib.Net.Firewall.FirewallFilterBuilder]::new()
        $builder.Name = $Name
        $builder.Description = $Description
        switch ($PSCmdlet.ParameterSetName) {
            "FromLayerKey" {
                $builder.LayerKey = $LayerKey.Id
            }
            "FromAleLayer" {
                $builder.LayerKey = Get-FwGuid -AleLayer $AleLayer
            }
        }

        $builder.SubLayerKey = $SubLayerKey.Id
        $builder.FilterKey = $Key
        $builder.ActionType = $ActionType
        if ($null -ne $Condition) {
            $builder.Conditions.AddRange($Condition.Conditions)
        }
        $builder.Weight = $Weight
        $builder.Flags = $Flags
        $builder.ProviderKey = $ProviderKey
        $Engine.AddFilter($builder)
    }
    catch {
        Write-Error $_
    }
}

Register-ArgumentCompleter -CommandName Add-FwFilter -ParameterName LayerKey -ScriptBlock $layer_completer
Register-ArgumentCompleter -CommandName Add-FwFilter -ParameterName SubLayerKey -ScriptBlock $sublayer_completer

<#
.SYNOPSIS
Delete a firewall filter.
.DESCRIPTION
This cmdlet deletes a firewall filter from an engine.
.PARAMETER Engine
The firewall engine.
.PARAMETER Key
Specify the filter's key.
.PARAMETER Id
Specify the filter's ID.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Remove-FwFilter -Engine $engine -Key "DB498708-9100-42F6-BC13-15E0A240D0ED"
Delete a filter by its key.
.EXAMPLE
Remove-FwFilter -Engine $engine -Id 12345
Delete a filter by its ID.
#>
function Remove-FwFilter {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, ParameterSetName="FromId")]
        [uint64]$Id,
        [parameter(Mandatory, ParameterSetName="FromKey")]
        [guid]$Key
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromKey" {
            $Engine.DeleteFilter($Key)
        }
        "FromId" {
            $Engine.DeleteFilter($Id)
        }
    }
}

<#
.SYNOPSIS
Format firewall filters.
.DESCRIPTION
This cmdlet formats a list of firewall filters.
.PARAMETER Filter
The list of filters to format.
.PARAMETER FormatSecurityDescriptor
Format any security descriptor condition values.
.PARAMETER Summary
Format the security descriptor in summary format.
.INPUTS
None
.OUTPUTS
string
.EXAMPLE
Format-FwFilter -Filter $fs
Format a list of firewall filters.
#>
function Format-FwFilter {
    [CmdletBinding(DefaultParameterSetName="NoSd")]
    param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Net.Firewall.FirewallFilter[]]$Filter,
        [parameter(Mandatory, ParameterSetName="FormatSd")]
        [switch]$FormatSecurityDescriptor,
        [parameter(ParameterSetName="FormatSd")]
        [switch]$Summary
    )

    PROCESS {
        foreach($f in $Filter) {
            Write-Output "Name       : $($f.Name)"
            Write-Output "Action Type: $($f.ActionType)"
            Write-Output "Key        : $($f.Key)"
            Write-Output "Id         : $($f.FilterId)"
            Write-Output "Description: $($f.Description)"
            Write-Output "Layer      : $($f.LayerKeyName)"
            Write-Output "Sub Layer  : $($f.SubLayerKeyName)"
            Write-Output "Flags      : $($f.Flags)"
            Write-Output "Weight     : $($f.EffectiveWeight)"
            if ($f.IsCallout) {
                Write-Output "Callout Key: $($f.CalloutKeyName)"
            }
            if ($f.Conditions.Count -gt 0) {
                Write-Output "Conditions :"
                Format-ObjectTable -InputObject $f.Conditions
                if ($FormatSecurityDescriptor) {
                    foreach($cond in $f.Conditions) {
                        if ($cond.Value.Value -is [NtCoreLib.Security.Authorization.SecurityDescriptor]) {
                            Format-NtSecurityDescriptor -SecurityDescriptor $cond.Value.Value -DisplayPath $cond.FieldKeyName -Summary:$Summary
                        }
                    }
                }
            }
            Write-Output ""
        }
    }
}

<#
.SYNOPSIS
Create a firewall condition builder.
.DESCRIPTION
This cmdlet creates a new firewall condition builder. Use Add-FwCondition to add a condition to it.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallConditionBuilder
.EXAMPLE
New-FwConditionBuilder
Create a condition builder.
.EXAMPLE
$builder = New-FwConditionBuilder | Add-FwCondition -Filename "c:\windows\notepad.exe" -PassThru
Create a filter condition builder and add a filter condition for the notepad executable.
#>
function New-FwConditionBuilder {
    [NtCoreLib.Net.Firewall.FirewallConditionBuilder]::new()
}

<#
.SYNOPSIS
Add a firewall condition to a template.
.DESCRIPTION
This cmdlet adds a firewall condition for a template.
.PARAMETER Builder
The condition builder/template to add the condition to.
.PARAMETER MatchType
The match operation for the condition.
.PARAMETER Filename
The path to an executable file to match.
.PARAMETER AppId
The path to an executable file to match using the native format.
.PARAMETER UserId
The security descriptor to check against the local user ID.
.PARAMETER RemoteUserId
The security descriptor to check against the remote user ID.
.PARAMETER ProtocolType
The type of IP protocol.
.PARAMETER IPAddress
The remote IP address.
.PARAMETER Port
The remote TCP/UDP port.
.PARAMETER LocalIPAddress
The local IP address.
.PARAMETER LocalPort
The local TCP/UDP port.
.PARAMETER IPAddress
The local IP address.
.PARAMETER Port
The local TCP/UDP port.
.PARAMETER Token
The token for a token information condition for user ID.
.PARAMETER RemoteToken
The token for a token information condition for remote user ID.
.PARAMETER MachineToken
The token for a token information condition for remote machine ID.
.PARAMETER PackageSid
The token's package SID.
.PARAMETER ConditionFlags
Specify condition flags to match.
.PARAMETER Process
Specify process to populate from. Adds token information and app ID.
.PARAMETER ProcessId
Specify process ID to populate from. Adds token information and app ID.
.PARAMETER PassThru
Pass through the condition builder/template.
.INPUTS
NtCoreLib.Net.Firewall.FirewallConditionBuilder
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallConditionBuilder
.EXAMPLE
Add-FwCondition $builder -Filename "c:\windows\notepad.exe"
Add a filter condition for the notepad executable.
.EXAMPLE
Add-FwCondition $builder -Filename "c:\windows\notepad.exe" -MatchType NotEqual
Add a filter condition which doesn't match the notepad executable.
.EXAMPLE
Add-FwCondition $builder -ProtocolType Tcp
Add a filter condition for the TCP protocol.
#>
function Add-FwCondition {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtCoreLib.Net.Firewall.FirewallConditionBuilder]$Builder,
        [NtCoreLib.Net.Firewall.FirewallMatchType]$MatchType = "Equal",
        [switch]$PassThru,
        [parameter(Mandatory, ParameterSetName="FromFilename")]
        [string]$Filename,
        [parameter(Mandatory, ParameterSetName="FromAppId")]
        [string]$AppId,
        [parameter(Mandatory, ParameterSetName="FromUserId")]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$UserId,
        [parameter(Mandatory, ParameterSetName="FromRemoteUserId")]
        [NtCoreLib.Security.Authorization.SecurityDescriptor]$RemoteUserId,
        [parameter(Mandatory, ParameterSetName="FromProtocolType")]
        [System.Net.Sockets.ProtocolType]$ProtocolType,
        [parameter(Mandatory, ParameterSetName="FromConditionFlags")]
        [NtCoreLib.Net.Firewall.FirewallConditionFlags]$ConditionFlags,
        [parameter(ParameterSetName="FromRemoteEndpoint")]
        [System.Net.IPAddress]$IPAddress,
        [parameter(ParameterSetName="FromRemoteEndpoint")]
        [int]$Port = -1,
        [parameter(ParameterSetName="FromLocalEndpoint")]
        [System.Net.IPAddress]$LocalIPAddress,
        [parameter(ParameterSetName="FromLocalEndpoint")]
        [int]$LocalPort = -1,
        [parameter(Mandatory, ParameterSetName="FromToken")]
        [NtCoreLib.NtToken]$Token,
        [parameter(Mandatory, ParameterSetName="FromRemoteToken")]
        [NtCoreLib.NtToken]$RemoteToken,
        [parameter(Mandatory, ParameterSetName="FromMachineToken")]
        [NtCoreLib.NtToken]$MachineToken,
        [parameter(Mandatory, ParameterSetName="FromPackageSid")]
        [NtObjectManager.Utils.Firewall.FirewallPackageSid]$PackageSid,
        [parameter(Mandatory, ParameterSetName="FromProcess")]
        [NtCoreLib.NtProcess]$Process,
        [parameter(Mandatory, ParameterSetName="FromProcessID")]
        [alias("pid")]
        [int]$ProcessId,
        [parameter(Mandatory, ParameterSetName="FromNetEventType")]
        [NtCoreLib.Net.Firewall.FirewallNetEventType]$NetEventType
    )

    try {
        switch($PSCmdlet.ParameterSetName) {
            "FromFilename" {
                $Builder.AddFilename($MatchType, $Filename)
            }
            "FromAppId" {
                $Builder.AddAppId($MatchType, $AppId)
            }
            "FromUserId" {
                $Builder.AddUserId($MatchType, $UserId)
            }
            "FromRemoteUserId" {
                $Builder.AddRemoteUserId($MatchType, $RemoteUserId)
            }
            "FromProtocolType" {
                $Builder.AddProtocolType($MatchType, $ProtocolType)
            }
            "FromConditionFlags" {
                $Builder.AddConditionFlags($MatchType, $ConditionFlags)
            }
            "FromRemoteEndpoint" {
                if ($null -ne $IPAddress) {
                    $Builder.AddIpAddress($MatchType, $true, $IPAddress)
                }
                if ($Port -ge 0) {
                    $Builder.AddPort($MatchType, $true, $Port)
                }
            }
            "FromLocalEndpoint" {
                if ($null -ne $LocalIPAddress) {
                    $Builder.AddIpAddress($MatchType, $false, $LocalIPAddress)
                }
                if ($LocalPort -ge 0) {
                    $Builder.AddPort($MatchType, $false, $LocalPort)
                }
            }
            "FromToken" {
                $Builder.AddUserToken($MatchType, $Token)
            }
            "FromRemoteToken" {
                $Builder.AddRemoteUserToken($MatchType, $RemoteToken)
            }
            "FromMachineToken" {
                $Builder.AddRemoteMachineToken($MatchType, $MachineToken)
            }
            "FromPackageSid" {
                $Builder.AddPackageSid($MatchType, $PackageSid.Sid)
            }
            "FromProcess" {
                $Builder.AddProcess($MatchType, $Process)
            }
            "FromProcessId" {
                $Builder.AddProcess($MatchType, $ProcessId)
            }
            "FromNetEventType" {
                $Builder.AddNetEventType($MatchType, $NetEventType)
            }
        }
        if ($PassThru) {
            $Builder
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get a firewall known GUID from a name.
.DESCRIPTION
This cmdlet gets a GUID from a name for well-known layer or sub-layer names.
.PARAMETER LayerName
The name of the layer.
.PARAMETER SubLayerName
The name of the sub-layer.
.PARAMETER AleLayer
The ALE layer type.
.INPUTS
None
.OUTPUTS
Guid
.EXAMPLE
Get-FwGuid -LayerName FWPM_LAYER_INBOUND_IPPACKET_V4
Get the GUID for a layer name.
.EXAMPLE
Get-FwGuid -AleLayer ConnectV4
Get the GUID for the ALE IPv4 connect layer.
.EXAMPLE
Get-FwGuid -SubLayerName FWPM_SUBLAYER_UNIVERSAL
Get the GUID for a sub-layer name.
#>
function Get-FwGuid {
    [CmdletBinding(DefaultParameterSetName="FromLayerName")]
    Param(
        [parameter(Mandatory, ParameterSetName="FromLayerName")]
        [string]$LayerName,
        [parameter(Mandatory, ParameterSetName="FromAleLayer")]
        [NtCoreLib.Net.Firewall.FirewallAleLayer]$AleLayer,
        [parameter(Mandatory, ParameterSetName="FromSubLayerName")]
        [string]$SubLayerName
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromLayerName" {
            [NtCoreLib.Net.Firewall.FirewallUtils]::GetKnownLayerGuid($LayerName)
        }
        "FromAleLayer" {
            [NtCoreLib.Net.Firewall.FirewallUtils]::GetLayerGuidForAleLayer($AleLayer)
        }
        "FromSubLayerName" {
            [NtCoreLib.Net.Firewall.FirewallUtils]::GetKnownSubLayerGuid($SubLayerName)
        }
    }
}

Register-ArgumentCompleter -CommandName Get-FwGuid -ParameterName LayerName -ScriptBlock $layer_completer
Register-ArgumentCompleter -CommandName Get-FwGuid -ParameterName SubLayerName -ScriptBlock $sublayer_completer

<#
.SYNOPSIS
Get an ALE endpoint.
.DESCRIPTION
This cmdlet gets a firewall ALE endpoint from an engine.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER Id
Specify the ALE endpoint ID.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallAleEndpoint[]
.EXAMPLE
Get-FwAleEndpoint -Engine $engine
Get all firewall ALE endpoints.
.EXAMPLE
Get-FwAleEndpoint -Engine $engine -Id 12345
Get the firewall ALE endpoint with ID 12345.
#>
function Get-FwAleEndpoint {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromId")]
        [uint64]$Id
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Engine.EnumerateAleEndpoints() | Write-Output
            }
            "FromId" {
                $Engine.GetAleEndpoint($Id)
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get token from firewall.
.DESCRIPTION
This cmdlet gets an access token from the firewall based on the modified ID.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER ModifiedId
Specify the token modified ID.
.PARAMETER AleEndpoint
Specify an ALE endpoint.
.PARAMETER Access
Specify Token access rights.
.INPUTS
None
.OUTPUTS
NtCoreLib.NtToken
.EXAMPLE
Get-FwToken -Engine $engine -ModifiedId 00000000-00012345
Get token from its modified ID.
.EXAMPLE
Get-FwToken -Engine $engine -AleEndpoint $ep
Get token from an ALE endpoint.
#>
function Get-FwToken {
    [CmdletBinding(DefaultParameterSetName="FromLuid")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromEndpoint")]
        [NtCoreLib.Net.Firewall.FirewallAleEndpoint]$AleEndpoint,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromLuid")]
        [NtCoreLib.Luid]$ModifiedId,
        [NtCoreLib.TokenAccessRights]$Access = "Query"
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine
        if ($PSCmdlet.ParameterSetName -eq "FromEndpoint") {
            $ModifiedId = $AleEndpoint.LocalTokenModifiedId
        }
        $Engine.OpenToken($ModifiedId, $Access)
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get an IKE security association.
.DESCRIPTION
This cmdlet gets an IKE security association from an engine. It can return a specific security association or all of them.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER Id
Specify the security association ID.
.PARAMETER SaLookupContext
Specify the the security association lookup context.
.PARAMETER Socket
Specify a secured socket to lookup the security association.
.PARAMETER Client
Specify a secured TCP client to lookup the security association.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.IkeSecurityAssociation[]
.EXAMPLE
Get-IkeSecurityAssociation -Engine $engine
Get all IKE security associations.
.EXAMPLE
Get-IkeSecurityAssociation -Engine $engine -Id 1234
Get an IKE security associations from an ID.
.EXAMPLE
Get-IkeSecurityAssociation -Engine $engine -Id 1234 -SaLookupContext "eebecc03-ced4-4380-819a-2734397b2b74"
Get an IKE security associations from an ID and lookup context.
.EXAMPLE
Get-IkeSecurityAssociation -Engine $engine -Socket $sock
Get an IKE security associations from a secured socket.
.EXAMPLE
Get-IkeSecurityAssociation -Engine $engine -Socket $sock -PeerAddress $ep
Get an IKE security associations from a secured socket with a specified peer address.
.EXAMPLE
Get-IkeSecurityAssociation -Engine $engine -Client $client
Get an IKE security associations from a secured TCP client.
#>
function Get-IkeSecurityAssociation {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromId")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromIdAndContext")]
        [uint64]$Id,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromIdAndContext")]
        [guid]$SaLookupContext,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromSocket")]
        [System.Net.Sockets.Socket]$Socket,
        [Parameter(ParameterSetName="FromSocket")]
        [System.Net.IPEndPoint]$PeerAddress,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromTcpClient")]
        [System.Net.Sockets.TcpClient]$Client
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine

        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Engine.EnumerateIkeSecurityAssociations() | Write-Output
            }
            "FromId" {
                $Engine.GetIkeSecurityAssociation($Id, $null)
            }
            "FromIdAndContext" {
                $Engine.GetIkeSecurityAssociation($Id, $SaLookupContext)
            }
            "FromSocket" {
                $r = Get-SocketSecurity -Socket $Socket -PeerAddress $PeerAddress
                $Engine.GetIkeSecurityAssociation($r.MmSaId, $r.SaLookupContext)
            }
            "FromTcpClient" {
                $r = Get-SocketSecurity -Client $Client
                $Engine.GetIkeSecurityAssociation($r.MmSaId, $r.SaLookupContext)
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get all firewall sessions.
.DESCRIPTION
This cmdlet gets all firewall sessions from an engine.
.PARAMETER Engine
The firewall engine to query.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallSession[]
.EXAMPLE
Get-FwSession -Engine $engine
Get all firewall sessions.
#>
function Get-FwSession {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Engine.EnumerateSessions() | Write-Output
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get all firewall network events.
.DESCRIPTION
This cmdlet gets all firewall network events from an engine.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER Template
Filter template for the network events.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallNetEvent[]
.EXAMPLE
Get-FwNetEvent -Engine $engine
Get all firewall network events.
#>
function Get-FwNetEvent {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [NtCoreLib.Net.Firewall.FirewallNetEventEnumTemplate]$Template
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Engine.EnumerateNetEvents($Template) | Write-Output
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Creates a network event listener.
.DESCRIPTION
This cmdlet creates a network event listenr from an engine. You pass the result to Read-FwNetEvent in a loop to read the events.
.PARAMETER Engine
The engine to create from.
.PARAMETER Template
Filter template for the network events.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallNetEventListener
.EXAMPLE
New-FwNetEventListener
Create a new firewall network event listener.
#>
function New-FwNetEventListener {
    [CmdletBinding()]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [NtCoreLib.Net.Firewall.FirewallNetEventEnumTemplate]$Template
    )
    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine

        $opt = Get-FwEngineOption -Engine $Engine -CollectNetEvents
        if (!$opt) {
            Write-Warning "CollectNetEvents option is not enabled. No events will be collected."
        }

        $Engine.SubscribeNetEvents($Template)
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Read a live firewall network events.
.DESCRIPTION
This cmdlet reads a live firewall network events from an engine.
.PARAMETER Listener
The firewall listener to read from.
.PARAMETER TimeoutMs
Specify a read timeout in milliseconds. -1 waits indefinitely.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallNetEvent
.EXAMPLE
Read-FwNetEvent -Listener $l
Read a live firewall network event.
#>
function Read-FwNetEvent {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, Position = 0)]
        [NtCoreLib.Net.Firewall.FirewallNetEventListener]$Listener,
        [int]$TimeoutMs = -1
    )

    $time_remaining = $TimeoutMs
    try {
        $ev = $null
        while($true) {
            $ev = $listener.ReadEvent(1000)
            if ($null -ne $ev) {
                break
            }
            if ($TimeoutMs -eq -1) {
                continue
            }
            $time_remaining -= 1000
            if ($time_remaining -le 0) {
                break;
            }
        }
        $ev
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Starts a network event listener.
.DESCRIPTION
This cmdlet starts a network event listener from an engine. It will read network events and print them to the console. It can also
capture the events into a variable.
.PARAMETER Engine
The engine to listen from.
.PARAMETER Variable
The name of a variable to put the read network events into.
.PARAMETER Template
Filter template for the network events.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Start-FwNetEventListener
Start a new firewall network event listener.
.EXAMPLE
Start-FwNetEventListener -Variable "events"
Start a new firewall network event listener and store the captured events in a variable.
#>
function Start-FwNetEventListener {
    [CmdletBinding()]
    param(
        [NtCoreLib.Net.Firewall.FirewallNetEventEnumTemplate]$Template,
        [string]$Variable,
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine
    )

    try {
        Use-NtObject($listener = New-FwNetEventListener -Engine $Engine -Template $Template) {
            if ($null -eq $listener) {
                return
            }
            $psvar = if ("" -ne $Variable) {
                Set-Variable -Name $Variable -Value @() -Scope global
                Get-Variable -Name $Variable
            }
            $shown_header = $false
            while($true) {
                $ev = Read-FwNetEvent -Listener $listener
                if ($null -eq $ev) {
                    break
                }
                if ($null -ne $psvar) {
                    $psvar.Value += @($ev)
                }
                Format-ObjectTable $ev -HideTableHeaders:$shown_header -NoTrailingLine | Out-Host
                $shown_header = $true
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Create a new template for enumerating network events.
.DESCRIPTION
This cmdlet creates a new template for enumerating network events, which can be used with Get-FwNetEvent and Start-FwNetEventListener.
.PARAMETER
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallNetEventEnumTemplate
.EXAMPLE
New-FwNetEventTemplate -StartTime ([datetime]::now.AddHours(-1))
Create a template for enumerating net events starting one hour ago.
#>
function New-FwNetEventTemplate {
    [CmdletBinding()]
    param(
        [datetime]$StartTime = [datetime]::FromFileTime(0),
        [datetime]$EndTime = [datetime]::MaxValue,
        [NtCoreLib.Net.Firewall.FirewallFilterCondition[]]$Condition
    )

    try {
        $template = [NtCoreLib.Net.Firewall.FirewallNetEventEnumTemplate]::new()
        $template.StartTime = $StartTime
        $template.EndTime = $EndTime
        if ($null -ne $Condition) {
            $template.Conditions.AddRange($Condition)
        }
        $template
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get an IPsec security association context.
.DESCRIPTION
This cmdlet gets an IPsec security association context from an engine.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER Id
Specify the IPsec security association context ID.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.IPsecSecurityAssociationContext[]
.EXAMPLE
Get-IPsecSaContext -Engine $engine
Get all security association context.
.EXAMPLE
Get-IPsecSaContext -Engine $engine -Id 12345
Get the security association context with ID 12345.
#>
function Get-IPsecSaContext {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromId")]
        [uint64]$Id
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Engine.EnumerateIPsecSecurityAssociationContexts() | Write-Output
            }
            "FromId" {
                $Engine.GetIPsecSecurityAssociationContext($Id)
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get a firewall engine option.
.DESCRIPTION
This cmdlet gets a firewall engine option.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER Option
Specify the option to query.
.PARAMETER CollectNetEvents
Specify to get the CollectNetEvents option.
.PARAMETER NetEventMatchAnyKeywords
Specify to get the NetEventMatchAnyKeywords option.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallValue
.EXAMPLE
Get-FwEngineOption -Option MonitorIPsecConnections
Get MonitorIPsecConnections option.
.EXAMPLE
Get-FwEngineOption -CollectNetEvents
Get CollectNetEvents option.
.EXAMPLE
Get-FwEngineOption -NetEventMatchAnyKeywords
Get NetEventMatchAnyKeywords option.
#>
function Get-FwEngineOption {
    [CmdletBinding(DefaultParameterSetName="FromOption")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromOption")]
        [NtCoreLib.Net.Firewall.FirewallEngineOption]$Option,
        [parameter(Mandatory, ParameterSetName="FromCollect")]
        [switch]$CollectNetEvents,
        [parameter(Mandatory, ParameterSetName="FromKeywords")]
        [switch]$NetEventMatchAnyKeywords
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine
        switch($PSCmdlet.ParameterSetName) {
            "FromOption" {
                $Engine.GetOption($Option)
            }
            "FromCollect" {
                $Engine.GetCollectNetEvents()
            }
            "FromKeywords" {
                $Engine.GetNetEventMatchAnyKeywords()
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get a firewall engine option.
.DESCRIPTION
This cmdlet sets a firewall engine option.
.PARAMETER Engine
The firewall engine to set.
.PARAMETER Option
Specify the option to set.
.PARAMETER Value
Specify the value to set.
.PARAMETER CollectNetEvents
Specify to set the CollectNetEvents option.
.PARAMETER NetEventMatchAnyKeywords
Specify to set the NetEventMatchAnyKeywords option.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-FwEngineOption -Option MonitorIPsecConnections -Value $val
Set MonitorIPsecConnections option.
.EXAMPLE
Set-FwEngineOption -CollectNetEvents $true
Set CollectNetEvents option to true.
.EXAMPLE
Set-FwEngineOption -NetEventMatchAnyKeywords CapabilityDrop
Get NetEventMatchAnyKeywords option.
#>
function Set-FwEngineOption {
    [CmdletBinding(DefaultParameterSetName="FromOption")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromOption")]
        [NtCoreLib.Net.Firewall.FirewallEngineOption]$Option,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromOption")]
        [NtCoreLib.Net.Firewall.FirewallValue]$Value,
        [parameter(Mandatory, ParameterSetName="FromCollect")]
        [bool]$CollectNetEvents,
        [parameter(Mandatory, ParameterSetName="FromKeywords")]
        [NtCoreLib.Net.Firewall.FirewallNetEventKeywords]$NetEventMatchAnyKeywords
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine
        switch($PSCmdlet.ParameterSetName) {
            "FromOption" {
                $Engine.SetOption($Option, $Value)
            }
            "FromCollect" {
                $Engine.SetCollectNetEvents($CollectNetEvents)
            }
            "FromKeywords" {
                $Engine.SetNetEventMatchAnyKeywords($NetEventMatchAnyKeywords)
            }
        }
    } catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS
Get a firewall callouts.
.DESCRIPTION
This cmdlet gets a firewall callout from an engine. It can return a specific callout or all callouts.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER Key
Specify the callout key.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallCallout[]
.EXAMPLE
Get-FwCallout
Get all firewall callouts.
.EXAMPLE
Get-FwCallout -Key "eebecc03-ced4-4380-819a-2734397b2b74"
Get firewall callout from key.
#>
function Get-FwCallout {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, ParameterSetName="FromKey")]
        [NtObjectManager.Utils.Firewall.FirewallCalloutGuid]$Key
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine

        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Engine.EnumerateCallouts() | Write-Output
            }
            "FromKey" {
                $Engine.GetCallout($Key.Id)
            }
        }
    } catch {
        Write-Error $_
    }
}

Register-ArgumentCompleter -CommandName Get-FwCallout -ParameterName Key -ScriptBlock $callout_completer

<#
.SYNOPSIS
Get a firewall provider.
.DESCRIPTION
This cmdlet gets a firewall provider from an engine. It can return a specific provider or all providers.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER Key
Specify the provider key.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Firewall.FirewallSubLayer[]
.EXAMPLE
Get-FwProvider
Get all firewall providers.
#>
function Get-FwProvider {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [NtCoreLib.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, ParameterSetName="FromKey")]
        [Guid]$Key
    )

    try {
        $Engine = Get-FwEngineSingleton -Engine $Engine

        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Engine.EnumerateProviders() | Write-Output
            }
            "FromKey" {
                $Engine.GetProvider($Key)
            }
        }
    } catch {
        Write-Error $_
    }
}