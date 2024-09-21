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
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Class to represent an IKE security association.
    /// </summary>
    public sealed class IkeSecurityAssociation
    {
        /// <summary>
        /// ID for the security association.
        /// </summary>
        public ulong Id { get; }
        /// <summary>
        /// Key module type.
        /// </summary>
        public IkeExtKeyModuleType KeyModuleType { get; }

        /// <summary>
        /// The local address of the association.
        /// </summary>
        public IPAddress LocalAddress { get; }

        /// <summary>
        /// The remote address of the association.
        /// </summary>
        public IPAddress RemoteAddress { get; }

        /// <summary>
        /// Initiator cookie.
        /// </summary>
        public ulong InitiatorCookie { get; }

        /// <summary>
        /// Responder cookie.
        /// </summary>
        public ulong ResponderCookie { get; }

        /// <summary>
        /// IKE policy key,
        /// </summary>
        public Guid IkePolicyKey { get; }

        /// <summary>
        /// Virtual interface tunnel ID.
        /// </summary>
        public ulong VirtualIfTunnelId { get; }

        /// <summary>
        /// Correlation key.
        /// </summary>
        public byte[] CorrelationKey { get; }

        /// <summary>
        /// List of credentials.
        /// </summary>
        public IReadOnlyList<IkeCredentialPair> Credentials { get; }

        /// <summary>
        /// Cipher algorithm for the security association.
        /// </summary>
        public IkeExtCipherType CipherAlgorithm { get; }
        /// <summary>
        /// Length of the key.
        /// </summary>
        public int KeyLength { get; }
        /// <summary>
        /// Number of rounds.
        /// </summary>
        public int Rounds { get; }
        /// <summary>
        /// Integrity algorithm for the security association.
        /// </summary>
        public IkeextIntegrityType IntegrityAlgorithm { get; }
        /// <summary>
        /// Maximum lifetime in seconds.
        /// </summary>
        public uint MaxLifetime { get; }
        /// <summary>
        /// Diffie-Hellman group.
        /// </summary>
        public IkeExtDHGroup DiffieHellmanGroup { get; }
        /// <summary>
        /// Quick mode limit.
        /// </summary>
        public uint QuickModeLimit { get; }

        internal IkeSecurityAssociation(IKEEXT_SA_DETAILS1 sa_details)
        {
            Id = sa_details.saId;
            KeyModuleType = sa_details.keyModuleType;
            LocalAddress = FirewallUtils.GetAddress(sa_details.ikeTraffic.ipVersion, sa_details.ikeTraffic.localAddress);
            RemoteAddress = FirewallUtils.GetAddress(sa_details.ikeTraffic.ipVersion, sa_details.ikeTraffic.remoteAddress);
            InitiatorCookie = sa_details.cookiePair.initiator;
            ResponderCookie = sa_details.cookiePair.responder;
            IkePolicyKey = sa_details.ikePolicyKey;
            VirtualIfTunnelId = sa_details.virtualIfTunnelId;
            CorrelationKey = sa_details.correlationKey.ToArray();
            CipherAlgorithm = sa_details.ikeProposal.cipherAlgorithm.algoIdentifier;
            KeyLength = sa_details.ikeProposal.cipherAlgorithm.keyLen;
            Rounds = sa_details.ikeProposal.cipherAlgorithm.rounds;
            IntegrityAlgorithm = sa_details.ikeProposal.integrityAlgorithm.algoIdentifier;
            MaxLifetime = sa_details.ikeProposal.maxLifetimeSeconds;
            DiffieHellmanGroup = sa_details.ikeProposal.dhGroup;
            QuickModeLimit = sa_details.ikeProposal.quickModeLimit;

            List<IkeCredentialPair> credentials = new List<IkeCredentialPair>();
            if (sa_details.ikeCredentials.numCredentials > 0)
            {
                SafeHGlobalBuffer buf = new SafeHGlobalBuffer(sa_details.ikeCredentials.credentials, 1, false);
                buf.Initialize<IKEEXT_CREDENTIAL_PAIR1>((uint)sa_details.ikeCredentials.numCredentials);
                var arr = buf.ReadArray<IKEEXT_CREDENTIAL_PAIR1>(0, sa_details.ikeCredentials.numCredentials);
                credentials.AddRange(arr.Select(c => new IkeCredentialPair(c)));
            }
            Credentials = credentials.AsReadOnly();
        }
    }
}
