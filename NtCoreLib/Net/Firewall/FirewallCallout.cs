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
    /// Class to represent a firewall callout object.
    /// </summary>
    public sealed class FirewallCallout : FirewallObject
    {
        /// <summary>
        /// Flags for the callout.
        /// </summary>
        public FirewallCalloutFlags Flags { get; }

        /// <summary>
        /// Provider key.
        /// </summary>
        public Guid ProviderKey { get; }

        /// <summary>
        /// Provider data.
        /// </summary>
        public byte[] ProviderData { get; }

        /// <summary>
        /// Applicable layer key.
        /// </summary>
        public Guid ApplicableLayer { get; }

        /// <summary>
        /// Callout ID.
        /// </summary>
        public int CalloutId { get; }

        internal FirewallCallout(FWPM_CALLOUT0 callout, FirewallEngine engine, Func<SecurityInformation, bool, NtResult<SecurityDescriptor>> get_sd) 
            : base(callout.calloutKey, callout.displayData, NamedGuidDictionary.CalloutGuids.Value, engine, get_sd)
        {
            Flags = callout.flags;
            ProviderData = callout.providerData.ToArray();
            ProviderKey = callout.providerKey.ReadGuid() ?? Guid.Empty;
            ApplicableLayer = callout.applicableLayer;
            CalloutId = callout.calloutId;
        }
    }
}
