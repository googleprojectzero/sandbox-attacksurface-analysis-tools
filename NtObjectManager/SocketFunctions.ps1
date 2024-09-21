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
Get IPsec security information for a socket.
.DESCRIPTION
This cmdlet gets the IPsec security information for a socket.
.PARAMETER Socket
The socket to query.
.PARAMETER Client
The TCP client to query.
.PARAMETER PeerAddress
The IP peer address for UDP sockets.
.PARAMETER Access
The token access rights to query the peer tokens.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Sockets.Security.SocketSecurityInformation
.EXAMPLE
Get-SocketSecurity -Socket $sock
Get the security information for a socket.
.EXAMPLE
Get-SocketSecurity -Socket $sock -PeerAddress $ep
Get the security information for a socket with a peer address.
.EXAMPLE
Get-SocketSecurity -Socket $sock -Access Impersonate
Get the security information for a socket and query for peer tokens with Impersonate access.
.EXAMPLE
Get-SocketSecurity -Client $client
Get the security information for a TCP client.
#>
function Get-SocketSecurity { 
    [CmdletBinding(DefaultParameterSetName="FromSocket")]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromSocket")]
        [System.Net.Sockets.Socket]$Socket,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromTcpClient")]
        [System.Net.Sockets.TcpClient]$Client,
        [Parameter(ParameterSetName="FromSocket")]
        [System.Net.IPEndPoint]$PeerAddress,
        [NtCoreLib.TokenAccessRights]$Access = 0
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromSocket" {
            [NtCoreLib.Net.Sockets.Security.SocketSecurityUtils]::QuerySecurity($Socket, $PeerAddress, $Access)
        }
        "FromTcpClient" {
            [NtCoreLib.Net.Sockets.Security.SocketSecurityUtils]::QuerySecurity($Client, $Access)
        }
    }
}

<#
.SYNOPSIS
Set IPsec security information for a socket.
.DESCRIPTION
This cmdlet sets the IPsec security information for a socket.
.PARAMETER Socket
The socket to set.
.PARAMETER Client
The TCP client to set.
.PARAMETER Listener
The TCP listener to set.
.PARAMETER Flags
The flags for the security protocol.
.PARAMETER IpsecFlags
The flags for IPsec.
.PARAMETER MMPolicyKey
The MM policy key.
.PARAMETER QMPolicyKey
The QM policy key.
.PARAMETER Credentials
The user credentials.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-SocketSecurity -Socket $sock
Set default security information for a socket.
.EXAMPLE
Get-SocketSecurity -Socket $sock -SecurityProtocol IPsec
Set the IPsec security information for a socket.
#>
function Set-SocketSecurity { 
    [CmdletBinding(DefaultParameterSetName="FromSocket")]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromSocket")]
        [System.Net.Sockets.Socket]$Socket,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromTcpClient")]
        [System.Net.Sockets.TcpClient]$Client,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromTcpListener")]
        [System.Net.Sockets.TcpListener]$Listener,
        [NtCoreLib.Net.Sockets.Security.SocketSecuritySettingFlags]$Flags = 0,
        [NtCoreLib.Net.Sockets.Security.SocketSecurityIpsecFlags]$IpsecFlags = 0,
        [guid]$MMPolicyKey = [guid]::Empty,
        [guid]$QMPolicyKey = [guid]::Empty,
        [NtCoreLib.Win32.Security.Authentication.UserCredentials]$Credentials
    )

    $setting = [NtCoreLib.Net.Sockets.Security.SocketSecuritySettings]::new()
    $setting.Flags = $Flags
    $setting.IpsecFlags = $IpsecFlags
    $setting.MMPolicyKey = $MMPolicyKey
    $setting.QMPolicyKey = $QMPolicyKey
    $setting.Credentials = $Credentials

    switch($PSCmdlet.ParameterSetName) {
        "FromSocket" {
            [NtCoreLib.Net.Sockets.Security.SocketSecurityUtils]::SetSecurity($Socket, $setting)
        }
        "FromTcpClient" {
            [NtCoreLib.Net.Sockets.Security.SocketSecurityUtils]::SetSecurity($Client, $setting)
        }
        "FromTcpListener" {
            [NtCoreLib.Net.Sockets.Security.SocketSecurityUtils]::SetSecurity($Listener, $setting)
        }
    }
}

<#
.SYNOPSIS
Set IPsec target peer for a socket.
.DESCRIPTION
This cmdlet sets the IPsec security information for a socket.
.PARAMETER Socket
The socket to set.
.PARAMETER Client
The TCP client to set.
.PARAMETER Listener
The TCP listener to set.
.PARAMETER TargetName
The peer target name to set.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Set-SocketPeerTargetName -Socket $sock -TargetName "SERVER"
Set peer target name for a socket.
#>
function Set-SocketPeerTargetName { 
    [CmdletBinding(DefaultParameterSetName="FromSocket")]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromSocket")]
        [System.Net.Sockets.Socket]$Socket,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromTcpClient")]
        [System.Net.Sockets.TcpClient]$Client,
        [Parameter(Mandatory, Position = 0, ParameterSetName="FromTcpListener")]
        [System.Net.Sockets.TcpListener]$Listener,
        [Parameter(Mandatory, Position = 1)]
        [string]$TargetName
    )
    switch($PSCmdlet.ParameterSetName) {
        "FromSocket" {
            [NtCoreLib.Net.Sockets.Security.SocketSecurityUtils]::SetPeerTargetName($Socket, $TargetName)
        }
        "FromTcpClient" {
            [NtCoreLib.Net.Sockets.Security.SocketSecurityUtils]::SetPeerTargetName($Client, $TargetName)
        }
        "FromTcpListener" {
            [NtCoreLib.Net.Sockets.Security.SocketSecurityUtils]::SetPeerTargetName($Listener, $TargetName)
        }
    }
}

<#
.SYNOPSIS
Get the HyperV socket table.
.DESCRIPTION
This cmdlet gets the HyperV socket table, either for listeners or connected sockets. Must be run as an administrator.
.PARAMETER Listener
Get the list of listeners, otherwise get connected sockets.
.PARAMETER Partition
Get sockets for a specific partition.
.INPUTS
None
.OUTPUTS
NtCoreLib.Net.Sockets.HyperV.HyperVSocketTableEntry[]
#>
function Get-HyperVSocketTable {
    param(
        [switch]$Listener,
        [guid]$Partition = [guid]::Empty
    )
    [NtCoreLib.Net.Sockets.HyperV.HyperVSocketUtils]::GetSocketTable($Listener, $Partition) | Write-Output
}

<#
.SYNOPSIS
Get the HyperV socket local addresses.
.DESCRIPTION
This cmdlet gets the HyperV socket local addresses. If not parameters specified then it'll return the local address.
.PARAMETER Parent
Get the parent addresss.
.PARAMETER SiloHost
Get the parent address.
.INPUTS
None
.OUTPUTS
Guid?
#>
function Get-HyperVSocketAddress {
    [CmdletBinding(DefaultParameterSetName="LocalAddress")]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName="ParentAddress")]
        [switch]$Parent,
        [Parameter(Mandatory, Position = 0, ParameterSetName="SiloHostAddress")]
        [switch]$SiloHost
    )
    if ($Parent) {
        [NtCoreLib.Net.Sockets.HyperV.HyperVSocketUtils]::ParentAddress
    } elseif($SiloHost) {
        [NtCoreLib.Net.Sockets.HyperV.HyperVSocketUtils]::SiloHostAddress
    } else {
        [NtCoreLib.Net.Sockets.HyperV.HyperVSocketUtils]::LocalAddress
    }
}