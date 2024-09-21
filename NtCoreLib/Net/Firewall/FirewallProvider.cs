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

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Class to represent a firewall provider.
    /// </summary>
    public sealed class FirewallProvider : FirewallObject
    {
        /// <summary>
        /// Name of the service which implements the provider.
        /// </summary>
        public string ServiceName { get; }

        /// <summary>
        /// Flags for the provider.
        /// </summary>
        public FirewallProviderFlags Flags { get; }

        /// <summary>
        /// Provider data.
        /// </summary>
        public byte[] ProviderData { get; }

        internal FirewallProvider(FWPM_PROVIDER0 provider, FirewallEngine engine, Func<SecurityInformation, bool, NtResult<SecurityDescriptor>> get_sd)
            : base(provider.providerKey, provider.displayData, new NamedGuidDictionary(), engine, get_sd)
        {
            ServiceName = provider.serviceName ?? string.Empty;
            Flags = provider.flags;
            ProviderData = provider.providerData.ToArray();
        }
    }
}
