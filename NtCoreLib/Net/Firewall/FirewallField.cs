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
    /// Represents a firewall field schema.
    /// </summary>
    public struct FirewallField
    {
        /// <summary>
        /// The field's key.
        /// </summary>
        public Guid Key { get; }
        /// <summary>
        /// The name of the key if known.
        /// </summary>
        public string KeyName { get; }
        /// <summary>
        /// The type of the field.
        /// </summary>
        public FirewallFieldType Type { get; }
        /// <summary>
        /// The data type of the field.
        /// </summary>
        public FirewallDataType DataType { get; }

        internal FirewallField(FWPM_FIELD0 field)
        {
            Key = field.fieldKey.ReadGuid() ?? Guid.Empty;
            KeyName = NamedGuidDictionary.ConditionGuids.Value.GetName(Key);
            Type = field.type;
            DataType = field.dataType;
        }
    }
}
