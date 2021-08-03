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

using NtApiDotNet.Utilities.Reflection;
using System;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// IPsec SA bundle flags.
    /// </summary>
    [Flags]
    public enum IPsecSecurityAssociationBundleFlags
    {
        None = 0,
        /// <summary>
        /// Negotiation discovery is enabled in secure ring.
        /// </summary>
        [SDKName("IPSEC_SA_BUNDLE_FLAG_ND_SECURE")]
        NDSecure = 0x00000001,
        /// <summary>
        /// Negotiation discovery in enabled in the untrusted perimeter zone.
        /// </summary>
        [SDKName("IPSEC_SA_BUNDLE_FLAG_ND_BOUNDARY")]
        NDBoundary = 0x00000002,
        /// <summary>
        /// Peer is in untrusted perimeter zone ring and a network address translation (NAT) is in the way. Used with negotiation discovery.
        /// </summary>
        [SDKName("IPSEC_SA_BUNDLE_FLAG_ND_PEER_NAT_BOUNDARY")]
        NDPeerNatBoundary = 0x00000004,
        /// <summary>
        /// Indicates that this is an SA for connections that require guaranteed encryption.
        /// </summary>
        [SDKName("IPSEC_SA_BUNDLE_FLAG_GUARANTEE_ENCRYPTION")]
        GuaranteeEncryption = 0x00000008,
        /// <summary>
        /// Indicates that this is an SA to an NLB server.
        /// </summary>
        [SDKName("IPSEC_SA_BUNDLE_FLAG_NLB")]
        NLB = 0x00000010,
        /// <summary>
        /// Indicates that this SA should bypass machine LUID verification.
        /// </summary>
        [SDKName("IPSEC_SA_BUNDLE_FLAG_NO_MACHINE_LUID_VERIFY")]
        NoMachineLuidVerify = 0x00000020,
        /// <summary>
        /// Indicates that this SA should bypass impersonation LUID verification.
        /// </summary>
        [SDKName("IPSEC_SA_BUNDLE_FLAG_NO_IMPERSONATION_LUID_VERIFY")]
        NoImpersonationLuidVerify = 0x00000040,
        /// <summary>
        /// Indicates that this SA should bypass explicit credential handle matching.
        /// </summary>
        [SDKName("IPSEC_SA_BUNDLE_FLAG_NO_EXPLICIT_CRED_MATCH")]
        NoExplicitCredMatch = 0x00000080,
        /// <summary>
        /// Allows an SA formed with a peer name to carry traffic that does not have an associated peer target.
        /// </summary>
        [SDKName("IPSEC_SA_BUNDLE_FLAG_ALLOW_NULL_TARGET_NAME_MATCH")]
        AllowNullTargetNameMatch = 0x00000200,
        /// <summary>
        /// Clears the DontFragment bit on the outer IP header of an IPsec-tunneled packet. This flag is applicable only to tunnel mode SAs.
        /// </summary>
        [SDKName("IPSEC_SA_BUNDLE_FLAG_CLEAR_DF_ON_TUNNEL")]
        ClearDFOnTunnel = 0x00000400,
        /// <summary>
        /// Default encapsulation ports (4500 and 4000) can be used when matching this SA with packets on outbound connections that do not have an associated IPsec-NAT-shim context.
        /// </summary>
        [SDKName("IPSEC_SA_BUNDLE_FLAG_ASSUME_UDP_CONTEXT_OUTBOUND")]
        AssumeUdpContextOutbound = 0x00000800,
        /// <summary>
        /// Peer has negotiation discovery enabled, and is on a perimeter network.
        /// </summary>
        [SDKName("IPSEC_SA_BUNDLE_FLAG_ND_PEER_BOUNDARY")]
        NDPeerBoundary = 0x00001000,
        /// <summary>
        /// Suppresses the duplicate SA deletion logic. THis logic is performed by the kernel when an outbound SA is added, to prevent unnecessary duplicate SAs.
        /// </summary>
        [SDKName("IPSEC_SA_BUNDLE_FLAG_SUPPRESS_DUPLICATE_DELETION")]
        SuppressDuplicateDeletion = 0x00002000,
        /// <summary>
        /// 	Indicates that the peer computer supports negotiating a separate SA for connections that require guaranteed encryption.
        /// </summary>
        [SDKName("IPSEC_SA_BUNDLE_FLAG_PEER_SUPPORTS_GUARANTEE_ENCRYPTION")]
        PeerSupportsGuaranteeEncryption = 0x00004000,
        [SDKName("IPSEC_SA_BUNDLE_FLAG_FORCE_INBOUND_CONNECTIONS")]
        ForceInboundConnections = 0x00008000,
        [SDKName("IPSEC_SA_BUNDLE_FLAG_FORCE_OUTBOUND_CONNECTIONS")]
        ForceOutboundConnections = 0x00010000,
        [SDKName("IPSEC_SA_BUNDLE_FLAG_FORWARD_PATH_INITIATOR")]
        ForwardPathInitiator = 0x00020000,
        [SDKName("IPSEC_SA_BUNDLE_FLAG_ENABLE_OPTIONAL_ASYMMETRIC_IDLE")]
        EnableOptionalAsymmetricIdle = 0x0040000,
        [SDKName("IPSEC_SA_BUNDLE_FLAG_USING_DICTATED_KEYS")]
        UsingDictatedKeys = 0x00080000,
        [SDKName("IPSEC_SA_BUNDLE_FLAG_LOCALLY_DICTATED_KEYS")]
        LocallyDictatedKeys = 0x00100000,
        [SDKName("IPSEC_SA_BUNDLE_FLAG_SA_OFFLOADED")]
        SAOffloaded = 0x00200000,
        [SDKName("IPSEC_SA_BUNDLE_FLAG_IP_IN_IP_PKT")]
        IpInIpPkt = 0x00400000,
    }
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member