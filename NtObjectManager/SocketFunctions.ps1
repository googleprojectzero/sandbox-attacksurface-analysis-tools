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
NtApiDotNet.Net.Sockets.SocketSecurityInformation
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
        [NtApiDotNet.TokenAccessRights]$Access = 0
    )

    switch($PSCmdlet.ParameterSetName) {
        "FromSocket" {
            [NtApiDotNet.Net.Sockets.SocketSecurityUtils]::QuerySecurity($Socket, $PeerAddress, $Access)
        }
        "FromTcpClient" {
            [NtApiDotNet.Net.Sockets.SocketSecurityUtils]::QuerySecurity($Client, $Access)
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
        [NtApiDotNet.Net.Sockets.SocketSecuritySettingFlags]$Flags = 0,
        [NtApiDotNet.Net.Sockets.SocketSecurityIpsecFlags]$IpsecFlags = 0,
        [guid]$MMPolicyKey = [guid]::Empty,
        [guid]$QMPolicyKey = [guid]::Empty,
        [NtApiDotNet.Win32.Security.Authentication.UserCredentials]$Credentials
    )

    $setting = [NtApiDotNet.Net.Sockets.SocketSecuritySettings]::new()
    $setting.Flags = $Flags
    $setting.IpsecFlags = $IpsecFlags
    $setting.MMPolicyKey = $MMPolicyKey
    $setting.QMPolicyKey = $QMPolicyKey
    $setting.Credentials = $Credentials

    switch($PSCmdlet.ParameterSetName) {
        "FromSocket" {
            [NtApiDotNet.Net.Sockets.SocketSecurityUtils]::SetSecurity($Socket, $setting)
        }
        "FromTcpClient" {
            [NtApiDotNet.Net.Sockets.SocketSecurityUtils]::SetSecurity($Client, $setting)
        }
        "FromTcpListener" {
            [NtApiDotNet.Net.Sockets.SocketSecurityUtils]::SetSecurity($Listener, $setting)
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
            [NtApiDotNet.Net.Sockets.SocketSecurityUtils]::SetPeerTargetName($Socket, $TargetName)
        }
        "FromTcpClient" {
            [NtApiDotNet.Net.Sockets.SocketSecurityUtils]::SetPeerTargetName($Client, $TargetName)
        }
        "FromTcpListener" {
            [NtApiDotNet.Net.Sockets.SocketSecurityUtils]::SetPeerTargetName($Listener, $TargetName)
        }
    }
}