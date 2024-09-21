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

using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authenticode
{
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

        private static object GetValue(ImagePolicyEntryType type, IMAGE_POLICY_ENTRY_UNION union)
        {
            switch (type)
            {
                case ImagePolicyEntryType.Bool:
                    return union.BoolValue;
                case ImagePolicyEntryType.Int16:
                    return union.Int16Value;
                case ImagePolicyEntryType.Int32:
                    return union.Int32Value;
                case ImagePolicyEntryType.Int64:
                    return union.Int64Value;
                case ImagePolicyEntryType.Int8:
                    return union.Int8Value;
                case ImagePolicyEntryType.UInt16:
                    return union.UInt16Value;
                case ImagePolicyEntryType.UInt32:
                    return union.UInt32Value;
                case ImagePolicyEntryType.UInt64:
                    return union.UInt64Value;
                case ImagePolicyEntryType.UInt8:
                    return union.UInt8Value;
                case ImagePolicyEntryType.UnicodeString:
                    return Marshal.PtrToStringUni(union.UnicodeStringValue);
                case ImagePolicyEntryType.AnsiString:
                    return Marshal.PtrToStringAnsi(union.AnsiStringValue);
                default:
                    return null;
            }
        }

        internal ImagePolicyEntry(ImagePolicyEntryType type, ImagePolicyId policy_id, IMAGE_POLICY_ENTRY_UNION union)
        {
            Type = type;
            PolicyId = policy_id;
            Value = GetValue(type, union);
        }
    }
}
