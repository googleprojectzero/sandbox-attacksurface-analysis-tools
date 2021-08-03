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

using NtApiDotNet.Utilities.Memory;
using System;
using System.Net;
using System.Net.Sockets;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Class to represent the details of an IPsec security association.
    /// </summary>
    public sealed class IPsecSecurityAssociation
    {
        /// <summary>
        /// Directory of SA.
        /// </summary>
        public FirewallDirectionType Direction { get; }

        /// <summary>
        /// Local endpoint.
        /// </summary>
        public IPEndPoint LocalEndpoint { get; }

        /// <summary>
        /// Remote endpoint.
        /// </summary>
        public IPEndPoint RemoteEndpoint { get; }

        /// <summary>
        /// Traffic type.
        /// </summary>
        public IPsecTrafficType TrafficType { get; }

        /// <summary>
        /// Traffic type ID.
        /// </summary>
        public ulong TrafficTypeId { get; }

        /// <summary>
        /// IP protocol type.
        /// </summary>
        public ProtocolType IpProtocol { get; }

        /// <summary>
        /// Interface LUID.
        /// </summary>
        public long LocalIfLuid { get; }

        /// <summary>
        /// Real interface profile ID.
        /// </summary>
        public uint RealIfProfileId { get; }

        /// <summary>
        /// The SA bundle.
        /// </summary>
        public IPsecSecurityAssociationBundle Bundle { get; }

        /// <summary>
        /// Local IPv4 UDP encapsulation port.
        /// </summary>
        public int LocalUdpEncapPort { get; }

        /// <summary>
        /// Remote IPv4 UDP encapsulation port.
        /// </summary>
        public int RemoteUdpEncapPort { get; }

        /// <summary>
        /// Transport filter.
        /// </summary>
        public FirewallFilter TransportFilter { get; }

        /// <summary>
        /// Virtual interface tunnel ID.
        /// </summary>
        public ulong VirtualIfTunnelId { get; }

        /// <summary>
        /// Traffic selector ID.
        /// </summary>
        public ulong TrafficSelectorId { get; }

        internal IPsecSecurityAssociation(IPSEC_SA_DETAILS1 details, Func<FWPM_FILTER0, FirewallFilter> get_filter)
        {
            Direction = details.saDirection;
            LocalEndpoint = FirewallUtils.GetEndpoint(details.traffic.ipVersion, 
                details.traffic.localAddrV4, details.traffic.localAddrV6, details.traffic.localPort);
            RemoteEndpoint = FirewallUtils.GetEndpoint(details.traffic.ipVersion,
                details.traffic.remoteAddrV4, details.traffic.remoteAddrV6, details.traffic.remotePort);
            IpProtocol = (ProtocolType)details.traffic.ipProtocol;
            LocalIfLuid = details.traffic.localIfLuid;
            RealIfProfileId = details.traffic.realIfProfileId;
            TrafficType = details.traffic.trafficType;
            TrafficTypeId = details.traffic.trafficTypeId;
            if (details.transportFilter != IntPtr.Zero)
            {
                TransportFilter = get_filter(details.transportFilter.ReadStruct<FWPM_FILTER0>());
            }
            Bundle = new IPsecSecurityAssociationBundle(details.saBundle);
            var virt_if = details.virtualIfTunnelInfo.ReadStruct<IPSEC_VIRTUAL_IF_TUNNEL_INFO0>();
            VirtualIfTunnelId = virt_if.virtualIfTunnelId;
            TrafficSelectorId = virt_if.trafficSelectorId;
            if (details.ipVersion == FirewallIpVersion.V4)
            {
                var udp_enc = details.udpEncapsulation.ReadStruct<IPSEC_V4_UDP_ENCAPSULATION0>();
                LocalUdpEncapPort = udp_enc.localUdpEncapPort;
                RemoteUdpEncapPort = udp_enc.remoteUdpEncapPort;
            }
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The overridden ToString method.</returns>
        public override string ToString()
        {
            return $"{TrafficType} - {RemoteEndpoint}";
        }
    }
}
