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
    public struct FirewallFilterCondition : ICloneable
    {
        #region Public Properties
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
        #endregion

        #region Internal Members
        internal FirewallFilterCondition(FWPM_FILTER_CONDITION0 condition) 
            : this(condition.matchType, condition.fieldKey, new FirewallValue(condition.conditionValue, condition.fieldKey))
        {
        }

        internal FWPM_FILTER_CONDITION0 ToStruct(DisposableList list)
        {
            return new FWPM_FILTER_CONDITION0
            {
                fieldKey = FieldKey,
                matchType = MatchType,
                conditionValue = Value.ToStruct(list)
            };
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="match_type">The condition match type.</param>
        /// <param name="field_key">The field key.</param>
        /// <param name="value">The value.</param>
        public FirewallFilterCondition(FirewallMatchType match_type, Guid field_key, FirewallValue value)
        {
            MatchType = match_type;
            FieldKey = field_key;
            FieldKeyName = NamedGuidDictionary.ConditionGuids.Value.GetName(FieldKey);
            Value = value;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The condition as a string.</returns>
        public override string ToString()
        {
            return FieldKeyName;
        }
        #endregion

        #region Interface Implementations
        object ICloneable.Clone()
        {
            return new FirewallFilterCondition(MatchType, FieldKey, Value.CloneValue());
        }
        #endregion
    }
}
