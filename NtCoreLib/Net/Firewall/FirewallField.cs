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

using NtCoreLib.Utilities.Memory;
using System;

namespace NtCoreLib.Net.Firewall;

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

    /// <summary>
    ///  Is the field value "raw" data?
    /// </summary>
    public bool IsRawData => Type.HasFlag(FirewallFieldType.RawData);

    /// <summary>
    /// Is the field value an IP address?
    /// </summary>
    public bool IsIPAddress => Type.HasFlag(FirewallFieldType.IPAddress);

    /// <summary>
    /// Is the field value a bitflag?
    /// </summary>
    public bool IsFlags => Type.HasFlag(FirewallFieldType.Flags);

    /// <summary>
    /// Tests whether a FirewallDataType supports being compared to another data type in a filter condition.
    /// </summary>
    /// <param name="other_type">A data type used in filter condition</param>
    /// <returns>True if data types comparable, otherwise false.</returns>
    public bool SupportsComparisonWithType(FirewallDataType other_type)
    {
        return DataType switch
        {
            // Generally, the data types must be the same.
            var t when t == other_type => true,

            // Raw address values can be compared against address masks
            FirewallDataType.UInt32 when IsIPAddress => other_type == FirewallDataType.V4AddrMask,
            FirewallDataType.ByteArray16 when IsIPAddress => other_type == FirewallDataType.V6AddrMask,

            // Token information can be compared against security descriptors in filter contexts.
            FirewallDataType.TokenInformation => other_type == FirewallDataType.SecurityDescriptor,
            FirewallDataType.TokenAccessInformation => other_type == FirewallDataType.SecurityDescriptor,

            _ => false,
        };
    }

    /// <summary>
    /// Identifies whether the field can be matched in a filter condition using the specified match type
    /// </summary>
    /// <param name="match_type">The match type</param>
    /// <returns>True if compatible, otherwise false</returns>
    public bool SupportsMatchType(FirewallMatchType match_type)
    {
        return match_type switch
        {
            // All data types support FWP_MATCH_EQUA
            FirewallMatchType.Equal => true,

            // Only the FWP_UNICODE_STRING_TYPE data type supports FWP_MATCH_EQUAL_CASE_INSENSITIVE.
            FirewallMatchType.EqualCaseInsensitive => DataType == FirewallDataType.UnicodeString,

            // Only sortable data types support FWP_MATCH_{NOT_EQUAL|GREATER|LESS|RANGE}.
            (
                FirewallMatchType.NotEqual or
                FirewallMatchType.Greater or
                FirewallMatchType.Less or
                FirewallMatchType.GreaterOrEqual or
                FirewallMatchType.LessOrEqual or
                FirewallMatchType.Range
            ) => DataType.IsSortable(),

            // Only unsigned integer data types support FWP_MATCH_FLAGS_*
            (
                FirewallMatchType.FlagsAllSet or
                FirewallMatchType.FlagsAnySet or
                FirewallMatchType.FlagsNoneSet
             ) => IsFlags && DataType.IsUnsignedInteger(),

            // The types FWP_BYTE_BLOB_TYPE (when it contains a string) and FWP_UNICODE_STRING_TYPE support this match type.
            FirewallMatchType.Prefix or FirewallMatchType.NotPrefix => DataType switch
            {
                FirewallDataType.ByteBlob when !IsIPAddress => true,
                FirewallDataType.UnicodeString => true,
                _ => false
            },

            _ => throw new ArgumentException($"Unknown match type {match_type}.")
        };
    }

    internal FirewallField(FWPM_FIELD0 field)
    {
        Key = field.fieldKey.ReadGuid() ?? Guid.Empty;
        KeyName = NamedGuidDictionary.ConditionGuids.Value.GetName(Key);
        Type = field.type;
        DataType = field.dataType;
    }
}
