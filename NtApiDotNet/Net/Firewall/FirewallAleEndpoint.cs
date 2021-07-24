//  Copyright 2021 Google LLC. All Rights Reserved.
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

using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Class to represent a firewall ALE endpoint.
    /// </summary>
    public sealed class FirewallAleEndpoint
    {
        /// <summary>
        /// The ID of the endpoint.
        /// </summary>
        public ulong EndpointId { get; }
        /// <summary>
        /// The local endpoint.
        /// </summary>
        public IPEndPoint LocalEndpoint { get; }
        /// <summary>
        /// The remote endpoint.
        /// </summary>
        public IPEndPoint RemoteEndpoint { get; }
        /// <summary>
        /// The protocol type.
        /// </summary>
        public ProtocolType IpProtocol { get; }
        /// <summary>
        /// The LUID for the token associated with the endpoint.
        /// </summary>
        public Luid LocalTokenModifiedId { get; }
        /// <summary>
        /// The IPsec security association identifier.
        /// </summary>
        public ulong MmSaId { get; }
        /// <summary>
        /// The IPsec security association identifier to expire.
        /// </summary>
        public ulong QmSaId { get; }
        /// <summary>
        /// The IPsec status of the endpoint.
        /// </summary>
        public uint IPsecStatus { get; }
        /// <summary>
        /// Flags.
        /// </summary>
        public uint Flags { get; }
        /// <summary>
        /// Associated application.
        /// </summary>
        public string AppId { get; }
        /// <summary>
        /// Filename of AppId.
        /// </summary>
        public string FileName => Path.GetFileName(AppId);

        internal FirewallAleEndpoint(FWPS_ALE_ENDPOINT_PROPERTIES0 ep)
        {
            EndpointId = ep.endpointId;
            LocalEndpoint = FirewallUtils.GetEndpoint(ep.ipVersion, ep.localAddress, ep.localPort);
            RemoteEndpoint = FirewallUtils.GetEndpoint(ep.ipVersion, ep.remoteAddress, ep.remotePort);
            IpProtocol = (ProtocolType)ep.ipProtocol;
            LocalTokenModifiedId = new Luid(ep.localTokenModifiedId);
            MmSaId = ep.mmSaId;
            QmSaId = ep.qmSaId;
            IPsecStatus = ep.ipsecStatus;
            Flags = ep.flags;
            AppId = Encoding.Unicode.GetString(ep.appId.ToArray()).TrimEnd('\0');
        }
    }
}
