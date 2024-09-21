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
    /// Class to represent a firewall sublayer.
    /// </summary>
    public sealed class FirewallSubLayer : FirewallObject
    {
        /// <summary>
        /// Sub-layer flags.
        /// </summary>
        public FirewallSubLayerFlags Flags { get; }
        /// <summary>
        /// The provider key.
        /// </summary>
        public Guid ProviderKey { get; }
        /// <summary>
        /// Provider data.
        /// </summary>
        public byte[] ProviderData { get; }
        /// <summary>
        /// Weight of the sub-layer.
        /// </summary>
        public int Weight { get; }

        internal FirewallSubLayer(FWPM_SUBLAYER0 sublayer, FirewallEngine engine, Func<SecurityInformation, bool, NtResult<SecurityDescriptor>> get_sd) 
            : base(sublayer.subLayerKey, sublayer.displayData, NamedGuidDictionary.SubLayerGuids.Value, engine, get_sd)
        {
            if (sublayer.providerKey != IntPtr.Zero)
            {
                ProviderKey = new Guid(NtProcess.Current.ReadMemory(sublayer.providerKey.ToInt64(), 16));
            }
            ProviderData = sublayer.providerData.ToArray();
            Flags = sublayer.flags;
            Weight = sublayer.weight;
        }
    }
}
