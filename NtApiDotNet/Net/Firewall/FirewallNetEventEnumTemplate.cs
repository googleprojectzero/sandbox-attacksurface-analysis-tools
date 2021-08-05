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
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Template for network event enumeration.
    /// </summary>
    public sealed class FirewallNetEventEnumTemplate : FirewallConditionBuilder, IFirewallEnumTemplate<FirewallNetEvent>
    {
        /// <summary>
        /// Start time for events.
        /// </summary>
        public DateTime StartTime { get; set; }

        /// <summary>
        /// End time for event.s
        /// </summary>
        public DateTime EndTime { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public FirewallNetEventEnumTemplate()
        {
            StartTime = DateTime.FromFileTime(0);
            EndTime = DateTime.MaxValue;
        }

        SafeBuffer IFirewallEnumTemplate<FirewallNetEvent>.ToTemplateBuffer(DisposableList list)
        {
            var template = new FWPM_NET_EVENT_ENUM_TEMPLATE0
            {
                startTime = new Luid(StartTime.ToFileTime()),
                endTime = new Luid(EndTime.ToFileTime())
            };

            if (Conditions.Count > 0)
            {
                template.numFilterConditions = Conditions.Count;
                template.filterCondition = list.AddList(Conditions.Select(c => c.ToStruct(list))).DangerousGetHandle();
            }

            return list.AddStructureRef(template);
        }

        Func<FirewallNetEvent, bool> IFirewallEnumTemplate<FirewallNetEvent>.GetFilterFunc(DisposableList list)
        {
            return null;
        }
    }
}
