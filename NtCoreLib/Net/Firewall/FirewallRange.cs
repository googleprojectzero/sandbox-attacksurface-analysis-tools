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
    /// A firewall value range.
    /// </summary>
    public struct FirewallRange : ICloneable
    {
        /// <summary>
        /// The low value.
        /// </summary>
        public FirewallValue Low { get; }
        /// <summary>
        /// The high value.
        /// </summary>
        public FirewallValue High { get; }

        internal FirewallRange(FWP_RANGE0 range, Guid condition_key) 
            : this(new FirewallValue(range.valueLow, condition_key), 
                  new FirewallValue(range.valueHigh, condition_key))
        {
        }

        internal FirewallRange(FirewallValue low, FirewallValue high)
        {
            Low = low;
            High = high;
        }

        internal FWP_RANGE0 ToStruct(DisposableList list)
        {
            return new FWP_RANGE0() {
                valueLow = Low.ToStruct(list),
                valueHigh = High.ToStruct(list)
            };
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The range as a string.</returns>
        public override string ToString()
        {
            return $"Low: {Low.ContextValue} High: {High.ContextValue}";
        }

        object ICloneable.Clone()
        {
            return new FirewallRange(Low.CloneValue(), High.CloneValue());
        }
    }
}
