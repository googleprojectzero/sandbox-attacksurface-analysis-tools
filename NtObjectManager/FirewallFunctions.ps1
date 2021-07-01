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
NtApiDotNet.Net.Firewall.FirewallEngine
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
        [NtApiDotNet.Win32.Rpc.Transport.RpcAuthenticationType]$AuthnService = "WinNT",
        [NtApiDotNet.Win32.Security.Authentication.UserCredentials]$Credentials,
        [switch]$Dynamic
    )

    $session = if ($Dynamic) {
        [NtApiDotNet.Net.Firewall.FirewallSession]::new("Dynamic")
    }

    [NtApiDotNet.Net.Firewall.FirewallEngine]::Open($ServerName, $AuthnService, $Credentials, $session)
}

<#
.SYNOPSIS
Get a firewall layer.
.DESCRIPTION
This cmdlet gets a firewall layer from an engine. It can return a specific layer or all layers.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER Key
Specify the layer key.
.PARAMETER Name
Specify the well-known name of the layer.
.PARAMETER Id
Specify the ID of the layer.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Net.Firewall.FirewallLayer[]
.EXAMPLE
Get-FwLayer -Engine $engine
Get all firewall layers.
.EXAMPLE
Get-FwLayer -Engine $engine -Key "c38d57d1-05a7-4c33-904f-7fbceee60e82"
Get firewall layer from key.
.EXAMPLE
Get-FwLayer -Engine $engine -Name "FWPM_LAYER_ALE_AUTH_CONNECT_V4"
Get firewall layer from name.
.EXAMPLE
Get-FwLayer -Engine $engine -Id 1234
Get firewall layer from its ID.
#>
function Get-FwLayer {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [parameter(Mandatory, Position = 0)]
        [NtApiDotNet.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromKey")]
        [Guid]$Key,
        [parameter(Mandatory, ParameterSetName="FromName")]
        [string]$Name,
        [parameter(Mandatory, ParameterSetName="FromId")]
        [int]$Id
    )

    switch($PSCmdlet.ParameterSetName) {
        "All" {
            $Engine.EnumerateLayers() | Write-Output
        }
        "FromKey" {
            $Engine.GetLayer($Key)
        }
        "FromName" {
            $Engine.GetLayer($Name)
        }
        "FromId" {
            $Engine.GetLayer($Id)
        }
    }
}

<#
.SYNOPSIS
Get a firewall sub-layer.
.DESCRIPTION
This cmdlet gets a firewall sub-layer from an engine. It can return a specific sub-layer or all sub-layers.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER Key
Specify the sub-layer key.
.PARAMETER Name
Specify the well-known name of the sub-layer.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Net.Firewall.FirewallSubLayer[]
.EXAMPLE
Get-FwSubLayer -Engine $engine
Get all firewall sub-layers.
.EXAMPLE
Get-FwSubLayer -Engine $engine -Key "eebecc03-ced4-4380-819a-2734397b2b74"
Get firewall sub-layer from key.
.EXAMPLE
Get-FwSubLayer -Engine $engine -Name "FWPM_SUBLAYER_UNIVERSAL"
Get firewall sub-layer from name.
#>
function Get-FwSubLayer {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [parameter(Mandatory, Position = 0)]
        [NtApiDotNet.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromKey")]
        [Guid]$Key,
        [parameter(Mandatory, ParameterSetName="FromName")]
        [string]$Name
    )

    switch($PSCmdlet.ParameterSetName) {
        "All" {
            $Engine.EnumerateSubLayers() | Write-Output
        }
        "FromKey" {
            $Engine.GetSubLayer($Key)
        }
        "FromName" {
            $Engine.GetSubLayer($Name)
        }
    }
}

<#
.SYNOPSIS
Get firewall filters.
.DESCRIPTION
This cmdlet gets firewall filters layer from an engine. It can return a filter in a specific layer or for all layers.
.PARAMETER Engine
The firewall engine to query.
.PARAMETER LayerKey
Specify the layer key.
.PARAMETER Flags
Specify enumeration flags.
.PARAMETER ActionType
Specify enumeration action type.
.PARAMETER Layer
Specify a layer object to query the filters from.
.PARAMETER Key
Specify the filter's key.
.PARAMETER Id
Specify the filter's ID.
.PARAMETER Condition
Specify one or more conditions to check for when enumerating.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Net.Firewall.FirewallLayer[]
.EXAMPLE
Get-FwFilter -Engine $engine
Get all firewall filters.
.EXAMPLE
Get-FwFilter -Engine $engine -LayerKey "c38d57d1-05a7-4c33-904f-7fbceee60e82"
Get firewall filters from layer key.
#>
function Get-FwFilter {
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [parameter(Mandatory, Position = 0, ParameterSetName="All")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromLayerKey")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromLayerName")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromId")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromKey")]
        [NtApiDotNet.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, ParameterSetName="FromLayerKey")]
        [guid]$LayerKey,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromLayerName")]
        [string]$LayerName,
        [parameter(ParameterSetName="FromLayerKey")]
        [parameter(ParameterSetName="FromLayerName")]
        [NtApiDotNet.Net.Firewall.FilterEnumFlags]$Flags = "None",
        [parameter(ParameterSetName="FromLayerKey")]
        [parameter(ParameterSetName="FromLayerName")]
        [NtApiDotNet.Net.Firewall.FirewallActionType]$ActionType = "All",
        [parameter(Mandatory, Position = 0, ParameterSetName="FromLayer", ValueFromPipeline)]
        [NtApiDotNet.Net.Firewall.FirewallLayer[]]$Layer,
        [parameter(Mandatory, ParameterSetName="FromId")]
        [uint64]$Id,
        [parameter(Mandatory, ParameterSetName="FromKey")]
        [guid]$Key,
        [parameter(ParameterSetName="FromLayerKey")]
        [parameter(ParameterSetName="FromLayerName")]
        [NtApiDotNet.Net.Firewall.FirewallFilterCondition[]]$Condition
    )

    PROCESS {
        $layer_key = $null
        switch($PSCmdlet.ParameterSetName) {
            "All" {
                $Engine.EnumerateFilters() | Write-Output
            }
            "FromLayerKey" {
                $layer_key = $LayerKey
            }
            "FromLayerName" {
                $layer_key = $LayerName
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
        if ($null -ne $layer_key) {
            $template = [NtApiDotNet.Net.Firewall.FirewallFilterEnumTemplate]::new($layer_key)
            $template.Flags = $Flags
            $template.ActionType = $ActionType
            if ($null -ne $Condition) {
                $template.Conditions.AddRange($Condition)
            }
            $Engine.EnumerateFilters($template) | Write-Output
        }
    }
}

<#
.SYNOPSIS
Add a firewall filter.
.DESCRIPTION
This cmdlet adds a firewall filter.
.PARAMETER Engine
The firewall engine to add to.
.PARAMETER LayerKey
Specify the layer key
.PARAMETER Flags
Specify filters flags.
.PARAMETER ActionType
Specify action type.
.PARAMETER Key
Specify the filter's key.
.PARAMETER Id
Specify the filter's ID.
.PARAMETER Condition
Specify one or more conditions to check for when filtering..
.INPUTS
None
.OUTPUTS
uint64
#>
function Add-FwFilter {
    [CmdletBinding(DefaultParameterSetName="FromLayerName")]
    param(
        [parameter(Mandatory, Position = 0)]
        [NtApiDotNet.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 1)]
        [string]$Name,
        [string]$Description = "",
        [parameter(Mandatory, ParameterSetName="FromLayerKey")]
        [guid]$LayerKey,
        [parameter(Mandatory, ParameterSetName="FromLayerName")]
        [string]$LayerName,
        [parameter(Mandatory)]
        [guid]$SubLayerKey,
        [guid]$Key = [guid]::Empty,
        [NtApiDotNet.Net.Firewall.FirewallActionType]$ActionType = "Permit",
        [NtApiDotNet.Net.Firewall.FirewallFilterCondition[]]$Condition,
        [NtApiDotNet.Net.Firewall.FirewallValue]$Weight = [NtApiDotNet.Net.Firewall.FirewallValue]::Empty,
        [NtApiDotNet.Net.Firewall.FirewallFilterFlags]$Flags = 0
    )

    try {
        $builder = [NtApiDotNet.Net.Firewall.FirewallFilterBuilder]::new()
        $builder.Name = $Name
        $builder.Description = $Description
        switch($PSCmdlet.ParameterSetName) {
            "FromLayerKey" {
                $builder.LayerKey = $LayerKey
            }
            "FromLayerName" {
                $builder.SetLayerName($LayerName)
            }
        }
        $builder.SubLayerKey = $SubLayerKey
        $builder.FilterKey = $Key
        $builder.ActionType = $ActionType
        if ($null -ne $Condition) {
            $builder.Conditions.AddRange($Condition)
        }
        $builder.Weight = $Weight
        $builder.Flags = $Flags
        $Engine.AddFilter($builder)
    }
    catch {
        Write-Error $_
    }
}

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
        [NtApiDotNet.Net.Firewall.FirewallEngine]$Engine,
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
.INPUTS
None
.OUTPUTS
string
.EXAMPLE
Format-FwFilter -Filter $fs
Format a list of firewall filters.
#>
function Format-FwFilter {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [NtApiDotNet.Net.Firewall.FirewallFilter[]]$Filter
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
            if ($f.Conditions.Count -gt 0) {
                Write-Output "Conditions :"
                Format-ObjectTable -InputObject $f.Conditions
            }
            Write-Output ""
        }
    }
}

<#
.SYNOPSIS
Create a firewall filter condition.
.DESCRIPTION
This cmdlet creates a firewall filter condition for add or enumerating filters.
.PARAMETER MatchType
The match operation for the condition.
.PARAMETER Filename
The path to an executable file to match.
.PARAMETER AppId
The path to an executable file to match using the native format.
.INPUTS
None
.OUTPUTS
NtApiDotNet.Net.Firewall.FirewallFilterCondition
.EXAMPLE
New-FwFilterCondition -Filename "c:\windows\notepad.exe"
Create a filter condition for the notepad executable.
.EXAMPLE
New-FwFilterCondition -Filename "c:\windows\notepad.exe" -MatchType NotEqual
Create a filter condition which doesn't match the notepad executable.
.EXAMPLE
New-FwFilterCondition -ProtocolType Tcp
Create a filter condition for the TCP protocol.
#>
function New-FwFilterCondition {
    [CmdletBinding()]
    param(
        [NtApiDotNet.Net.Firewall.FirewallMatchType]$MatchType = "Equal",
        [parameter(Mandatory, ParameterSetName="FromFilename")]
        [string]$Filename,
        [parameter(Mandatory, ParameterSetName="FromAppId")]
        [string]$AppId,
        [parameter(Mandatory, ParameterSetName="FromUserId")]
        [NtApiDotNet.SecurityDescriptor]$UserId,
        [parameter(Mandatory, ParameterSetName="FromProtocolType")]
        [System.Net.Sockets.ProtocolType]$ProtocolType,
        [parameter(Mandatory, ParameterSetName="FromConditionFlags")]
        [NtApiDotNet.Net.Firewall.FirewallConditionFlags]$ConditionFlags,
        [parameter(Mandatory, ParameterSetName="FromIpAddress")]
        [System.Net.IPAddress]$IPAddress,
        [parameter(ParameterSetName="FromIpAddress")]
        [switch]$Remote,
        [parameter(Mandatory, ParameterSetName="FromTokenInformation")]
        [NtApiDotNet.NtToken]$TokenInformation
    )

    try {
        $builder = [NtApiDotNet.Net.Firewall.FirewallConditionBuilder]::new()
        switch($PSCmdlet.ParameterSetName) {
            "FromFilename" {
                $builder.AddFilename($MatchType, $Filename)
            }
            "FromAppId" {
                $builder.AddAppId($MatchType, $AppId)
            }
            "FromUserId" {
                $builder.AddUserId($MatchType, $UserId)
            }
            "FromProtocolType" {
                $builder.AddProtocolType($MatchType, $ProtocolType)
            }
            "FromConditionFlags" {
                $builder.AddConditionFlags($MatchType, $ConditionFlags)
            }
            "FromIpAddress" {
                $builder.AddIpAddress($MatchType, $Remote, $IPAddress)
            }
            "FromTokenInformation" {
                $builder.AddTokenInformation($MatchType, $TokenInformation)
            }
        }
        $builder.Conditions | Write-Output
    } catch {
        Write-Error $_
    }
}