//  Copyright 2020 Google Inc. All Rights Reserved.
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

using NtCoreLib.Image.Interop;
using NtCoreLib.Utilities.Memory;

namespace NtCoreLib.Image.Security;

/// <summary>
/// Image policy entry.
/// </summary>
public sealed class ImagePolicyEntry
{
    /// <summary>
    /// Type of entry.
    /// </summary>
    public ImagePolicyEntryType Type { get; }
    /// <summary>
    /// Policy ID.
    /// </summary>
    public ImagePolicyId PolicyId { get; }
    /// <summary>
    /// Value of entry.
    /// </summary>
    public object Value { get; }

    private static object GetValue(ImagePolicyEntryType type, IMAGE_POLICY_ENTRY_UNION union, IMemoryReader reader)
    {
        return type switch
        {
            ImagePolicyEntryType.Bool => union.BoolValue,
            ImagePolicyEntryType.Int16 => union.Int16Value,
            ImagePolicyEntryType.Int32 => union.Int32Value,
            ImagePolicyEntryType.Int64 => union.Int64Value,
            ImagePolicyEntryType.Int8 => union.Int8Value,
            ImagePolicyEntryType.UInt16 => union.UInt16Value,
            ImagePolicyEntryType.UInt32 => union.UInt32Value,
            ImagePolicyEntryType.UInt64 => union.UInt64Value,
            ImagePolicyEntryType.UInt8 => union.UInt8Value,
            ImagePolicyEntryType.UnicodeString => reader.ReadUnicodeStringZ(union.UnicodeStringValue),
            ImagePolicyEntryType.AnsiString => reader.ReadAnsiStringZ(union.AnsiStringValue),
            _ => null,
        };
    }

    internal ImagePolicyEntry(ImagePolicyEntryType type, ImagePolicyId policy_id, IMAGE_POLICY_ENTRY_UNION union, IMemoryReader reader)
    {
        Type = type;
        PolicyId = policy_id;
        Value = GetValue(type, union, reader);
    }
}
