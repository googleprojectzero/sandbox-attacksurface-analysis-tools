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

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Class to represent an IPsec kernel drop event.
    /// </summary>
    public sealed class FirewallNetEventIPsecKernelDrop : FirewallNetEvent
    {
        /// <summary>
        /// Failure error code.
        /// </summary>
        public NtStatus FailureStatus { get; }

        /// <summary>
        /// Connection direction.
        /// </summary>
        public FirewallDirectionType Direction { get; }

        /// <summary>
        /// Security parameter index.
        /// </summary>
        public uint Spi { get; }

        /// <summary>
        /// Filter ID.
        /// </summary>
        public ulong FilterId { get; }

        /// <summary>
        /// Layer ID.
        /// </summary>
        public ushort LayerId { get; }

        internal FirewallNetEventIPsecKernelDrop(IFwNetEvent net_event) : base(net_event)
        {
            var inner_event = net_event.Value.ReadStruct<FWPM_NET_EVENT_IPSEC_KERNEL_DROP0>();
            FailureStatus = inner_event.failureStatus;
            Direction = inner_event.direction;
            Spi = inner_event.spi;
            FilterId = inner_event.filterId;
            LayerId = inner_event.layerId;
        }
    }
}
