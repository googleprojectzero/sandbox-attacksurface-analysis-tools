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
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Class to represent a security association bundle.
    /// </summary>
    public sealed class IPsecSecurityAssociationBundle
    {
        /// <summary>
        /// Flags for the SA.
        /// </summary>
        public IPsecSecurityAssociationBundleFlags Flags { get; }

        /// <summary>
        /// SA lifetime in seconds.
        /// </summary>
        public uint LifetimeSeconds { get; }

        /// <summary>
        /// SA lifetime in KiB.
        /// </summary>
        public uint LifetimeKilobytes { get; }

        /// <summary>
        /// SA lifetime in packets.
        /// </summary>
        public uint LifetimePackets { get; }

        /// <summary>
        /// Idle timeout.
        /// </summary>
        public uint IdleTimeoutSeconds { get; }

        /// <summary>
        /// ND allow clear timeout.
        /// </summary>
        public uint NdAllowClearTimeoutSeconds { get; }

        /// <summary>
        /// Identity for IPsec SA.
        /// </summary>
        public IPsecIdentity Identity { get; }

        /// <summary>
        /// NAP context.
        /// </summary>
        public uint NapContext { get; }

        /// <summary>
        /// Quick-mode SA ID.
        /// </summary>
        public uint QmSaId { get; }

        /// <summary>
        /// Key module key.
        /// </summary>
        public Guid KeyModuleKey { get; }

        /// <summary>
        /// Key module state blob.
        /// </summary>
        public byte[] KeyModuleStateBlob { get; }

        /// <summary>
        /// List of security association parameters.
        /// </summary>
        public IReadOnlyList<IPsecSecurityAssociationParameter> SecurityParameters { get; }

        /// <summary>
        /// Peer V4 private address.
        /// </summary>
        public IPAddress PeerV4PrivateAddress { get; }

        /// <summary>
        /// Main-mode SA ID.
        /// </summary>
        public ulong MmSaId { get; }

        /// <summary>
        /// PFS group.
        /// </summary>
        public IPsecPerfectForwardSecrecyGroup PfsGroup { get; }

        /// <summary>
        /// SA lookup context.
        /// </summary>
        public Guid SaLookupContext { get; }

        /// <summary>
        /// QM filter ID.
        /// </summary>
        public ulong QmFilterId { get; }

        internal IPsecSecurityAssociationBundle(IPSEC_SA_BUNDLE1 bundle)
        {
            Flags = bundle.flags;
            LifetimeSeconds = bundle.lifetime.lifetimeSeconds;
            LifetimeKilobytes = bundle.lifetime.lifetimeKilobytes;
            LifetimePackets = bundle.lifetime.lifetimePackets;
            IdleTimeoutSeconds = bundle.idleTimeoutSeconds;
            NdAllowClearTimeoutSeconds = bundle.ndAllowClearTimeoutSeconds;
            NapContext = bundle.napContext;
            QmSaId = bundle.qmSaId;
            QmFilterId = bundle.qmFilterId;
            MmSaId = bundle.mmSaId;
            PfsGroup = bundle.pfsGroup;
            SaLookupContext = bundle.saLookupContext;
            var key_state = bundle.keyModuleState.ReadStruct<IPSEC_KEYMODULE_STATE0>();
            KeyModuleKey = key_state.keyModuleKey;
            KeyModuleStateBlob = key_state.stateBlob.ToArray();
            if (bundle.ipVersion == FirewallIpVersion.V4)
            {
                PeerV4PrivateAddress = new IPAddress(BitConverter.GetBytes(bundle.peerV4PrivateAddress).Reverse().ToArray());
            }
            else
            {
                PeerV4PrivateAddress = IPAddress.Any;
            }
            if (bundle.ipsecId != IntPtr.Zero)
            {
                Identity = new IPsecIdentity(bundle.ipsecId.ReadStruct<IPSEC_ID0>());
            }
            List<IPsecSecurityAssociationParameter> ps = new List<IPsecSecurityAssociationParameter>();
            if (bundle.numSAs > 0 && bundle.saList != IntPtr.Zero)
            {
                ps.AddRange(bundle.saList.ReadArray<IPSEC_SA0>(bundle.numSAs).Select(IPsecSecurityAssociationParameter.Create));
            }
            SecurityParameters = ps.AsReadOnly();
        }
    }
}
