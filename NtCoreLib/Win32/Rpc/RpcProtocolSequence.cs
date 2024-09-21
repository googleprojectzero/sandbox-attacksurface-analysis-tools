//  Copyright 2022 Google LLC. All Rights Reserved.
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

namespace NtApiDotNet.Win32.Rpc
{
    /// <summary>
    /// RPC protocol sequence constants.
    /// </summary>
    public static class RpcProtocolSequence
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        public const string DNetNSP = "ncacn_dnet_dsp";
        public const string Tcp = "ncacn_ip_tcp";
        public const string Udp = "ncacn_ip_udp";
        public const string NetbiosTcp = "ncacn_nb_tcp";
        public const string Spx = "ncacn_spx";
        public const string NetbiosIpx = "ncacn_np_ipx";
        public const string Ipx = "ncacg_ipx";
        public const string NamedPipe = "ncacn_np";
        public const string LRPC = "ncalrpc";
        public const string NetBIOS = "ncacn_nb_nb";
        public const string AppleTalkDSP = "ncacn_at_dsp";
        public const string AppleTalkDDP = "ncacg_at_ddp";
        public const string BanyanVinesSPP = "ncacn_vns_spp";
        public const string MessageQueue = "ncadg_mq";
        public const string Http = "ncacn_http";
        public const string Container = "ncacn_hvsocket";
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member

        /// <summary>
        /// Convert a protocol sequence id to a string.
        /// </summary>
        /// <param name="id">The RPC protocol sequence identifier.</param>
        /// <returns>The protocol sequence string.</returns>
        public static string IdToString(RpcProtocolSequenceIdentifier id)
        {
            switch (id)
            {
                case RpcProtocolSequenceIdentifier.DNetNSP: return DNetNSP;
                case RpcProtocolSequenceIdentifier.Tcp: return Tcp;
                case RpcProtocolSequenceIdentifier.Udp: return Udp;
                case RpcProtocolSequenceIdentifier.NetbiosTcp: return NetbiosTcp;
                case RpcProtocolSequenceIdentifier.Spx: return Spx;
                case RpcProtocolSequenceIdentifier.NetbiosIpx: return NetbiosIpx;
                case RpcProtocolSequenceIdentifier.Ipx: return Ipx;
                case RpcProtocolSequenceIdentifier.NamedPipe: return NamedPipe;
                case RpcProtocolSequenceIdentifier.LRPC: return LRPC;
                case RpcProtocolSequenceIdentifier.NetBIOS: return NetBIOS;
                case RpcProtocolSequenceIdentifier.AppleTalkDSP: return AppleTalkDSP;
                case RpcProtocolSequenceIdentifier.AppleTalkDDP: return AppleTalkDDP;
                case RpcProtocolSequenceIdentifier.BanyanVinesSPP: return BanyanVinesSPP;
                case RpcProtocolSequenceIdentifier.MessageQueue: return MessageQueue;
                case RpcProtocolSequenceIdentifier.Http: return Http;
                case RpcProtocolSequenceIdentifier.Container: return Container;
            }
            throw new ArgumentException($"Unsupported protocol sequence {id}");
        }

        /// <summary>
        /// Convert a protocol string to an id.
        /// </summary>
        /// <param name="protocol_sequence">The protocol sequence string.</param>
        /// <returns>The protocol sequence identifier.</returns>
        public static RpcProtocolSequenceIdentifier StringToId(string protocol_sequence)
        {
            switch (protocol_sequence?.ToLower())
            {
                case DNetNSP: return RpcProtocolSequenceIdentifier.DNetNSP;
                case Tcp: return RpcProtocolSequenceIdentifier.Tcp;
                case Udp: return RpcProtocolSequenceIdentifier.Udp;
                case NetbiosTcp: return RpcProtocolSequenceIdentifier.NetbiosTcp;
                case Spx: return RpcProtocolSequenceIdentifier.Spx;
                case NetbiosIpx: return RpcProtocolSequenceIdentifier.NetbiosIpx;
                case Ipx: return RpcProtocolSequenceIdentifier.Ipx;
                case NamedPipe: return RpcProtocolSequenceIdentifier.NamedPipe;
                case LRPC: return RpcProtocolSequenceIdentifier.LRPC;
                case NetBIOS: return RpcProtocolSequenceIdentifier.NetBIOS;
                case AppleTalkDSP: return RpcProtocolSequenceIdentifier.AppleTalkDSP;
                case AppleTalkDDP: return RpcProtocolSequenceIdentifier.AppleTalkDDP;
                case BanyanVinesSPP: return RpcProtocolSequenceIdentifier.BanyanVinesSPP;
                case MessageQueue: return RpcProtocolSequenceIdentifier.MessageQueue;
                case Http: return RpcProtocolSequenceIdentifier.Http;
                case Container: return RpcProtocolSequenceIdentifier.Container;
            }
            throw new ArgumentException($"Unsupported protocol sequence {protocol_sequence}");
        }
    }
}
