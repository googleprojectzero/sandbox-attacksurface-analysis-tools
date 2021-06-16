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
    /// Firewall filter condition.
    /// </summary>
    public struct FirewallFilterCondition
    {
        /// <summary>
        /// The match type.
        /// </summary>
        public FirewallMatchType MatchType { get; }

        /// <summary>
        /// The key of the field.
        /// </summary>
        public Guid FieldKey { get; }

        /// <summary>
        /// The field key name.
        /// </summary>
        public string FieldKeyName { get; }

        /// <summary>
        /// The value for the condition
        /// </summary>
        public FirewallValue Value { get; }

        internal FirewallFilterCondition(FWPM_FILTER_CONDITION0 condition)
        {
            MatchType = condition.matchType;
            FieldKey = condition.fieldKey;
            FieldKeyName = NamedGuidDictionary.ConditionGuids.Value.GetName(FieldKey);
            Value = new FirewallValue(condition.conditionValue, condition.fieldKey);
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The condition as a string.</returns>
        public override string ToString()
        {
            return FieldKeyName;
        }
    }
}
