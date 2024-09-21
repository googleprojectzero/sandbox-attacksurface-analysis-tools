//  Copyright 2021 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using NtCoreLib.Ndr.Marshal;
using NtCoreLib.Net.Sockets.HyperV;
using NtCoreLib.Win32.Rpc.EndpointMapper;
using System;
using System.Net.Sockets;

namespace NtCoreLib.Win32.Rpc.Transport;

/// <summary>
/// RPC client transport over HyperV sockets.
/// </summary>
public sealed class RpcHyperVClientTransport : RpcStreamSocketClientTransport
{
    #region Private Members
    private const ushort MaxXmitFrag = 5840;
    private const ushort MaxRecvFrag = 5840;

    private static Socket CreateSocket(HyperVEndPoint endpoint)
    {
        Socket socket = new(HyperVEndPoint.AF_HYPERV, 
            SocketType.Stream, HyperVEndPoint.HV_PROTOCOL_RAW);
        socket.Connect(endpoint);
        return socket;
    }

    private RpcServerProcessInformation GetServerProcess()
    {
        if (_socket.RemoteEndPoint is HyperVEndPoint ep)
        {
            foreach (var entry in HyperVSocketUtils.GetSocketTable(true, Guid.Empty))
            {
                if (entry.SystemId == ep.ServiceId)
                {
                    return new RpcServerProcessInformation(entry.ProcessId, 0);
                }
            }
        }
        throw new ArgumentException("Can't find local listener for Hyper-V socket.");
    }
    #endregion

    #region Constructors
    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="endpoint">The HyperV socket endpoint to connect to.</param>
    /// <param name="transport_security">The security for the transport.</param>
    /// <param name="config">The transport configuration for the connection.</param>
    public RpcHyperVClientTransport(HyperVEndPoint endpoint, RpcTransportSecurity transport_security, RpcConnectedClientTransportConfiguration config)
        : base(CreateSocket(endpoint), MaxRecvFrag, MaxXmitFrag, new NdrDataRepresentation(), transport_security, config)
    {
    }
    #endregion

    #region Public Properties
    /// <summary>
    /// Get the transport protocol sequence.
    /// </summary>
    public override string ProtocolSequence => RpcProtocolSequence.Container;

    /// <inheritdoc/>
    public override RpcServerProcessInformation ServerProcess => GetServerProcess();
    #endregion

    #region Internal Members
    internal static Guid ResolveVmId(string guid)
    {
        if (string.IsNullOrEmpty(guid))
            return HyperVSocketGuids.HV_GUID_LOOPBACK;

        return guid.ToLower() switch
        {
            "parent" => HyperVSocketGuids.HV_GUID_PARENT,
            "children" => HyperVSocketGuids.HV_GUID_CHILDREN,
            "silohost" => HyperVSocketGuids.HV_GUID_SILOHOST,
            "loopback" => HyperVSocketGuids.HV_GUID_LOOPBACK,
            _ => Guid.Parse(guid),
        };
    }
    #endregion
}
