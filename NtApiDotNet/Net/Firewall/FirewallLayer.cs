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

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Class to represent a firewall layer object.
    /// </summary>
    public sealed class FirewallLayer : FirewallObject
    {
        /// <summary>
        /// Layer flags.
        /// </summary>
        public FirewallLayerFlags Flags { get; }

        /// <summary>
        /// Default sub-layer key.
        /// </summary>
        public Guid DefaultSubLayerKey { get; }

        /// <summary>
        /// Enumerate filters for this layer.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of sorted filters.</returns>
        public NtResult<IEnumerable<FirewallFilter>> EnumerateFilters(bool throw_on_error)
        {
            FirewallFilterEnumTemplate template = new FirewallFilterEnumTemplate()
            {
                LayerKey = Key,
                Flags = FilterEnumFlags.Sorted
            };

            return _engine.EnumerateFilters(template, throw_on_error);
        }

        /// <summary>
        /// Enumerate filters for this layer.
        /// </summary>
        /// <returns>The list of sorted filters.</returns>
        public IEnumerable<FirewallFilter> EnumerateFilters()
        {
            return EnumerateFilters(true).Result;
        }

        internal FirewallLayer(FWPM_LAYER0 layer, FirewallEngine engine, Func<SecurityInformation, bool, NtResult<SecurityDescriptor>> get_sd) 
            : base(layer.layerKey, layer.displayData, NamedGuidDictionary.LayerGuids.Value, engine, get_sd)
        {
            Flags = layer.flags;
            DefaultSubLayerKey = layer.defaultSubLayerKey;
        }
    }
}
