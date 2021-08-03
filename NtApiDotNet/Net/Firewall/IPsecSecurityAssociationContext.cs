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

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Class to represent an IPsec security association context.
    /// </summary>
    public sealed class IPsecSecurityAssociationContext
    {
        /// <summary>
        /// ID of the context.
        /// </summary>
        public ulong Id { get; }

        /// <summary>
        /// Inbound security association.
        /// </summary>
        public IPsecSecurityAssociation Inbound { get; }

        /// <summary>
        /// Outbound security association.
        /// </summary>
        public IPsecSecurityAssociation Outbound { get; }

        internal IPsecSecurityAssociationContext(IPSEC_SA_CONTEXT1 context, Func<FWPM_FILTER0, FirewallFilter> get_filter)
        {
            Id = context.saContextId;
            if (context.inboundSa != IntPtr.Zero)
            {
                Inbound = new IPsecSecurityAssociation(context.inboundSa.ReadStruct<IPSEC_SA_DETAILS1>(), get_filter);
            }
            if (context.outboundSa != IntPtr.Zero)
            {
                Outbound = new IPsecSecurityAssociation(context.outboundSa.ReadStruct<IPSEC_SA_DETAILS1>(), get_filter);
            }
        }
    }
}
