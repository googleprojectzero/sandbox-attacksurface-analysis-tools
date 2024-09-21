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

namespace NtCoreLib.Win32.Rpc.EndpointMapper;

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
        return id switch
        {
            RpcProtocolSequenceIdentifier.DNetNSP => DNetNSP,
            RpcProtocolSequenceIdentifier.Tcp => Tcp,
            RpcProtocolSequenceIdentifier.Udp => Udp,
            RpcProtocolSequenceIdentifier.NetbiosTcp => NetbiosTcp,
            RpcProtocolSequenceIdentifier.Spx => Spx,
            RpcProtocolSequenceIdentifier.NetbiosIpx => NetbiosIpx,
            RpcProtocolSequenceIdentifier.Ipx => Ipx,
            RpcProtocolSequenceIdentifier.NamedPipe => NamedPipe,
            RpcProtocolSequenceIdentifier.LRPC => LRPC,
            RpcProtocolSequenceIdentifier.NetBIOS => NetBIOS,
            RpcProtocolSequenceIdentifier.AppleTalkDSP => AppleTalkDSP,
            RpcProtocolSequenceIdentifier.AppleTalkDDP => AppleTalkDDP,
            RpcProtocolSequenceIdentifier.BanyanVinesSPP => BanyanVinesSPP,
            RpcProtocolSequenceIdentifier.MessageQueue => MessageQueue,
            RpcProtocolSequenceIdentifier.Http => Http,
            RpcProtocolSequenceIdentifier.Container => Container,
            _ => throw new ArgumentException($"Unsupported protocol sequence {id}"),
        };
    }

    /// <summary>
    /// Convert a protocol string to an id.
    /// </summary>
    /// <param name="protocol_sequence">The protocol sequence string.</param>
    /// <returns>The protocol sequence identifier.</returns>
    public static RpcProtocolSequenceIdentifier StringToId(string protocol_sequence)
    {
        return (protocol_sequence?.ToLower()) switch
        {
            DNetNSP => RpcProtocolSequenceIdentifier.DNetNSP,
            Tcp => RpcProtocolSequenceIdentifier.Tcp,
            Udp => RpcProtocolSequenceIdentifier.Udp,
            NetbiosTcp => RpcProtocolSequenceIdentifier.NetbiosTcp,
            Spx => RpcProtocolSequenceIdentifier.Spx,
            NetbiosIpx => RpcProtocolSequenceIdentifier.NetbiosIpx,
            Ipx => RpcProtocolSequenceIdentifier.Ipx,
            NamedPipe => RpcProtocolSequenceIdentifier.NamedPipe,
            LRPC => RpcProtocolSequenceIdentifier.LRPC,
            NetBIOS => RpcProtocolSequenceIdentifier.NetBIOS,
            AppleTalkDSP => RpcProtocolSequenceIdentifier.AppleTalkDSP,
            AppleTalkDDP => RpcProtocolSequenceIdentifier.AppleTalkDDP,
            BanyanVinesSPP => RpcProtocolSequenceIdentifier.BanyanVinesSPP,
            MessageQueue => RpcProtocolSequenceIdentifier.MessageQueue,
            Http => RpcProtocolSequenceIdentifier.Http,
            Container => RpcProtocolSequenceIdentifier.Container,
            _ => throw new ArgumentException($"Unsupported protocol sequence {protocol_sequence}"),
        };
    }
}
