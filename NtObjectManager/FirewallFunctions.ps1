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
    [NtApiDotNet.Net.Firewall.FirewallUtils]::GetKnownLayerNames() | Where-Object { $_ -like "$wordToComplete*" }
}

$sublayer_completer = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    [NtApiDotNet.Net.Firewall.FirewallUtils]::GetKnownSubLayerNames() | Where-Object { $_ -like "$wordToComplete*" }
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
.PARAMETER AleLayer
Specify the ALE layer type.
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
        [parameter(Mandatory, ParameterSetName="FromAleLayer")]
        [NtApiDotNet.Net.Firewall.FirewallAleLayer]$AleLayer,
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
        "FromAleLayer" {
            $Engine.GetLayer($AleLayer)
        }
        "FromId" {
            $Engine.GetLayer($Id)
        }
    }
}

Register-ArgumentCompleter -CommandName Get-FwLayer -ParameterName Name -ScriptBlock $layer_completer

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

Register-ArgumentCompleter -CommandName Get-FwSubLayer -ParameterName Name -ScriptBlock $sublayer_completer

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
NtApiDotNet.Net.Firewall.FirewallLayer[]
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
        [parameter(Mandatory, Position = 0, ParameterSetName="All")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromLayerKey")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromId")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromKey")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromAleLayer")]
        [parameter(Mandatory, Position = 0, ParameterSetName="FromTemplate")]
        [NtApiDotNet.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromLayerKey")]
        [NtObjectManager.Utils.Firewall.FirewallLayerGuid]$LayerKey,
        [parameter(Mandatory, ParameterSetName="FromAleLayer")]
        [NtApiDotNet.Net.Firewall.FirewallAleLayer]$AleLayer,
        [parameter(Mandatory, Position = 0, ParameterSetName="FromLayer", ValueFromPipeline)]
        [NtApiDotNet.Net.Firewall.FirewallLayer[]]$Layer,
        [parameter(Mandatory, ParameterSetName="FromId")]
        [uint64]$Id,
        [parameter(Mandatory, ParameterSetName="FromKey")]
        [guid]$Key,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromTemplate")]
        [NtApiDotNet.Net.Firewall.FirewallFilterEnumTemplate]$Template,
        [parameter(ParameterSetName="FromLayerKey")]
        [parameter(ParameterSetName="FromAleLayer")]
        [switch]$Sorted
    )

    PROCESS {
        try {
            switch($PSCmdlet.ParameterSetName) {
                "All" {
                    $Engine.EnumerateFilters() | Write-Output
                }
                "FromLayerKey" {
                    $Template = [NtApiDotNet.Net.Firewall.FirewallFilterEnumTemplate]::new($LayerKey.Id)
                }
                "FromAleLayer" {
                    $Template = [NtApiDotNet.Net.Firewall.FirewallFilterEnumTemplate]::new($AleLayer)
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
.INPUTS
None
.OUTPUTS
NtApiDotNet.Net.Firewall.FirewallFilterEnumTemplate
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
        [NtApiDotNet.Net.Firewall.FirewallAleLayer]$AleLayer,
        [NtApiDotNet.Net.Firewall.FirewallFilterEnumFlags]$Flags = "None",
        [NtApiDotNet.Net.Firewall.FirewallActionType]$ActionType = "All",
        [NtApiDotNet.Net.Firewall.FirewallFilterCondition[]]$Condition,
        [NtApiDotNet.NtToken]$Token,
        [NtApiDotNet.NtToken]$RemoteToken
    )

    try {
        $template = switch($PSCmdlet.ParameterSetName) {
            "FromLayerKey" {
                [NtApiDotNet.Net.Firewall.FirewallFilterEnumTemplate]::new($LayerKey.Id)
            }
            "FromAleLayer" {
                [NtApiDotNet.Net.Firewall.FirewallFilterEnumTemplate]::new($AleLayer)
            }
        }
        $template.Flags = $Flags
        $template.ActionType = $ActionType
        if ($null -ne $Condition) {
            $template.Conditions.AddRange($Condition)
        }
        $template.Token = $Token
        $template.RemoteToken = $RemoteToken
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
Specify one or more conditions to check for when filtering..
.INPUTS
None
.OUTPUTS
uint64
#>
function Add-FwFilter {
    [CmdletBinding(DefaultParameterSetName="FromLayerKey")]
    param(
        [parameter(Mandatory, Position = 0)]
        [NtApiDotNet.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 1)]
        [string]$Name,
        [string]$Description = "",
        [parameter(Mandatory, ParameterSetName="FromLayerKey")]
        [NtObjectManager.Utils.Firewall.FirewallLayerGuid]$LayerKey,
        [parameter(Mandatory, ParameterSetName="FromAleLayer")]
        [NtApiDotNet.Net.Firewall.FirewallAleLayer]$AleLayer,
        [NtObjectManager.Utils.Firewall.FirewallSubLayerGuid]$SubLayerKey,
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
.PARAMETER FormatSecurityDescriptor
Format any security descriptor condition values.
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
        [NtApiDotNet.Net.Firewall.FirewallFilter[]]$Filter,
        [switch]$FormatSecurityDescriptor
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
                Write-Output "Callout Key: $($f.CalloutKey)"
            }
            if ($f.Conditions.Count -gt 0) {
                Write-Output "Conditions :"
                Format-ObjectTable -InputObject $f.Conditions
                if ($FormatSecurityDescriptor) {
                    foreach($cond in $f.Conditions) {
                        if ($cond.Value.Value -is [NtApiDotNet.SecurityDescriptor]) {
                            Format-NtSecurityDescriptor -SecurityDescriptor $cond.Value.Value -DisplayPath $cond.FieldKeyName
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
Create a firewall filter condition.
.DESCRIPTION
This cmdlet creates a firewall filter condition for add or enumerating filters.
.PARAMETER MatchType
The match operation for the condition.
.PARAMETER Filename
The path to an executable file to match.
.PARAMETER AppId
The path to an executable file to match using the native format.
.PARAMETER UserId
The security descriptor to check against the user ID. Can specify Remote to use remote user.
.PARAMETER ProtocolType
The type of IP protocol.
.PARAMETER IPAddress
The local IP address. Can specify Remote to use the remote IP address.
.PARAMETER Port
The local TCP/UDP port. Can specify Remote to use the remote IP address.
.PARAMETER Remote
Specify to change certain parameters to be remote from local.
.PARAMETER TokenInformation
The token for a token information condition.
.PARAMETER PackageSid
The token's package SID.
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
        [parameter(ParameterSetName="FromUserId")]
        [parameter(ParameterSetName="FromPort")]
        [switch]$Remote,
        [parameter(Mandatory, ParameterSetName="FromTokenInformation")]
        [NtApiDotNet.NtToken]$TokenInformation,
        [parameter(Mandatory, ParameterSetName="FromPackageSid")]
        [string]$PackageSid,
        [parameter(Mandatory, ParameterSetName="FromPort")]
        [int]$Port
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
                $builder.AddUserId($MatchType, $Remote, $UserId)
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
            "FromPackageSid" {
                $sid = $PackageSid
                if ($sid -ne "S-1-0-0") {
                    $sid = [NtApiDotNet.Win32.TokenUtils]::GetPackageSidFromName($PackageSid)
                }
                $builder.AddPackageSid($MatchType, $sid)
            }
            "FromPort" {
                $builder.AddPort($MatchType, $Remote, $Port)
            }
        }
        $builder.Conditions | Write-Output
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
        [NtApiDotNet.Net.Firewall.FirewallAleLayer]$AleLayer,
        [parameter(Mandatory, ParameterSetName="FromSubLayerName")]
        [string]$SubLayerName
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromLayerName" {
            [NtApiDotNet.Net.Firewall.FirewallUtils]::GetKnownLayerGuid($LayerName)
        }
        "FromAleLayer" {
            [NtApiDotNet.Net.Firewall.FirewallUtils]::GetLayerGuidForAleLayer($AleLayer)
        }
        "FromSubLayerName" {
            [NtApiDotNet.Net.Firewall.FirewallUtils]::GetKnownSubLayerGuid($SubLayerName)
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
NtApiDotNet.Net.Firewall.FirewallAleEndpoint[]
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
        [parameter(Mandatory, Position = 0)]
        [NtApiDotNet.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromId")]
        [uint64]$Id
    )

    switch($PSCmdlet.ParameterSetName) {
        "All" {
            $Engine.EnumerateAleEndpoints() | Write-Output
        }
        "FromId" {
            $Engine.GetAleEndpoint($Id)
        }
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
NtApiDotNet.NtToken
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
        [parameter(Mandatory, Position = 0)]
        [NtApiDotNet.Net.Firewall.FirewallEngine]$Engine,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromEndpoint")]
        [NtApiDotNet.Net.Firewall.FirewallAleEndpoint]$AleEndpoint,
        [parameter(Mandatory, Position = 1, ParameterSetName="FromLuid")]
        [NtApiDotNet.Luid]$ModifiedId,
        [NtApiDotNet.TokenAccessRights]$Access = "Query"
    )

    if ($PSCmdlet.ParameterSetName -eq "FromEndpoint") {
        $ModifiedId = $AleEndpoint.LocalTokenModifiedId
    }
    $Engine.OpenToken($ModifiedId, $Access)
}