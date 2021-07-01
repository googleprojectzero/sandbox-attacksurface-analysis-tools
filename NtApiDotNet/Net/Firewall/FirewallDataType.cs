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

using NtApiDotNet.Utilities.Reflection;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace NtApiDotNet.Net.Firewall
{
    public enum FirewallDataType
    {
        [SDKName("FWP_EMPTY")]
        Empty = 0,
        [SDKName("FWP_UINT8")]
        UInt8 = Empty + 1,
        [SDKName("FWP_UINT16")]
        UInt16 = UInt8 + 1,
        [SDKName("FWP_UINT32")]
        UInt32 = UInt16 + 1,
        [SDKName("FWP_UINT64")]
        UInt64 = UInt32 + 1,
        [SDKName("FWP_INT8")]
        Int8 = UInt64 + 1,
        [SDKName("FWP_INT16")]
        Int16 = Int8 + 1,
        [SDKName("FWP_INT32")]
        Int32 = Int16 + 1,
        [SDKName("FWP_INT64")]
        Int64 = Int32 + 1,
        [SDKName("FWP_FLOAT")]
        Float = Int64 + 1,
        [SDKName("FWP_DOUBLE")]
        Double = Float + 1,
        [SDKName("FWP_BYTE_ARRAY16_TYPE")]
        ByteArray16 = Double + 1,
        [SDKName("FWP_BYTE_BLOB_TYPE")]
        ByteBlob = ByteArray16 + 1,
        [SDKName("FWP_SID")]
        Sid = ByteBlob + 1,
        [SDKName("FWP_SECURITY_DESCRIPTOR_TYPE")]
        SecurityDescriptor = Sid + 1,
        [SDKName("FWP_TOKEN_INFORMATION_TYPE")]
        TokenInformation = SecurityDescriptor + 1,
        [SDKName("FWP_TOKEN_ACCESS_INFORMATION_TYPE")]
        TokenAccessInformation = TokenInformation + 1,
        [SDKName("FWP_UNICODE_STRING_TYPE")]
        UnicodeString = TokenAccessInformation + 1,
        [SDKName("FWP_BYTE_ARRAY6_TYPE")]
        ByteArray6 = UnicodeString + 1,
        [SDKName("FWP_BITMAP_INDEX_TYPE")]
        BitmapIndex = ByteArray6 + 1,
        [SDKName("FWP_BITMAP_ARRAY64_TYPE")]
        BitmapArray64 = BitmapIndex + 1,
        [SDKName("FWP_SINGLE_DATA_TYPE_MAX")]
        SingleDataTypeMax = 0xff,
        [SDKName("FWP_V4_ADDR_MASK")]
        V4AddrMask = SingleDataTypeMax + 1,
        [SDKName("FWP_V6_ADDR_MASK")]
        V6AddrMask = V4AddrMask + 1,
        [SDKName("FWP_RANGE_TYPE")]
        Range = V6AddrMask + 1
    }
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member