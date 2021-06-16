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
using System.Collections;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Firewall value.
    /// </summary>
    public struct FirewallValue
    {
        /// <summary>
        /// Type of the value.
        /// </summary>
        public FirewallDataType Type { get; }
        /// <summary>
        /// The raw value.
        /// </summary>
        public object Value { get; }
        /// <summary>
        /// The context specific value, might be the same as the original.
        /// </summary>
        public object ContextValue { get; }

        private static object SpecializeValue(FirewallDataType type, object value, Guid condition_key)
        {
            if (condition_key == Guid.Empty)
                return value;

            if (FirewallConditionGuids.IsIpAddressCondition(condition_key))
            {
                if (value is byte[] ba && (ba.Length == 4 || ba.Length == 16))
                {
                    return new IPAddress(ba);
                }
                else if (value is uint ui)
                {
                    ba = BitConverter.GetBytes(ui);
                    Array.Reverse(ba);
                    return new IPAddress(ba);
                }
                else if (!(value is FirewallRange) && !(value is FirewallAddressAndMask))
                {
                    System.Diagnostics.Trace.Write($"Invalid IP Address type: {value.GetType().FullName}");
                }
            }
            else if (FirewallConditionGuids.IsAppId(condition_key))
            {
                if (value is byte[] ba && (ba.Length % 2 == 0))
                {
                    return Encoding.Unicode.GetString(ba).TrimEnd('\0');
                }
            }
            else if (FirewallConditionGuids.IsGuid(condition_key))
            {
                if (value is byte[] ba && ba.Length == 16)
                {
                    return new Guid(ba);
                }
            }
            else if (condition_key == FirewallConditionGuids.FWPM_CONDITION_IP_PROTOCOL
                || condition_key == FirewallConditionGuids.FWPM_CONDITION_EMBEDDED_PROTOCOL)
            {
                if (value is byte b)
                {
                    return (ProtocolType)b;
                }
            }
            else if (condition_key == FirewallConditionGuids.FWPM_CONDITION_FLAGS)
            {
                if (value is uint ui)
                {
                    return (FirewallConditionFlags)ui;
                }
            }

            return value;
        }

        private static T ReadStruct<T>(IntPtr ptr)
        {
            return (T)Marshal.PtrToStructure(ptr, typeof(T));
        }

        private static byte[] ReadBytes(IntPtr ptr, int size)
        {
            if (size <= 0 || ptr == IntPtr.Zero)
            {
                return new byte[0];
            }
            byte[] ret = new byte[size];
            Marshal.Copy(ptr, ret, 0, ret.Length);
            return ret;
        }

        private static byte[] ReadBlob(IntPtr ptr)
        {
            var blob = ReadStruct<FWP_BYTE_BLOB>(ptr);
            return ReadBytes(blob.data, blob.size);
        }

        private static object ToObject(FirewallDataType type, FWP_VALUE0_UNION value, Guid condition_key)
        {
            switch (type)
            {
                case FirewallDataType.SecurityDescriptor:
                    return SecurityDescriptor.Parse(ReadBlob(value.sd), FirewallUtils.FirewallFilterType, false).GetResultOrDefault();
                case FirewallDataType.TokenInformation:
                    return new FirewallTokenInformation(ReadStruct<FWP_TOKEN_INFORMATION>(value.tokenInformation));
                case FirewallDataType.TokenAccessInformation:
                    return ReadBlob(value.tokenAccessInformation);
                case FirewallDataType.Sid:
                    return Sid.Parse(value.sid, false).GetResultOrDefault();
                case FirewallDataType.UInt8:
                    return value.uint8;
                case FirewallDataType.UInt16:
                    return value.uint16;
                case FirewallDataType.UInt32:
                    return value.uint32;
                case FirewallDataType.Int8:
                    return value.int8;
                case FirewallDataType.Int16:
                    return value.int16;
                case FirewallDataType.Int32:
                    return value.int32;
                case FirewallDataType.Range:
                    return new FirewallRange(ReadStruct<FWP_RANGE0>(value.rangeValue), condition_key);
                case FirewallDataType.ByteArray16:
                    return ReadBytes(value.byteArray16, 16);
                case FirewallDataType.ByteArray6:
                    return ReadBytes(value.byteArray6, 6);
                case FirewallDataType.UInt64:
                    return (ulong)Marshal.ReadInt64(value.uint64);
                case FirewallDataType.Int64:
                    return Marshal.ReadInt64(value.uint64);
                case FirewallDataType.ByteBlob:
                    return ReadBlob(value.byteBlob);
                case FirewallDataType.V4AddrMask:
                    return new FirewallAddressAndMask(ReadStruct<FWP_V4_ADDR_AND_MASK>(value.v4AddrMask));
                case FirewallDataType.V6AddrMask:
                    return new FirewallAddressAndMask(ReadStruct<FWP_V6_ADDR_AND_MASK>(value.v6AddrMask));
                case FirewallDataType.UnicodeString:
                    return Marshal.PtrToStringUni(value.unicodeString);
                case FirewallDataType.BitmapArray64:
                    return new BitArray(ReadStruct<FWP_BITMAP_ARRAY64>(value.bitmapArray64).bitmapArray64);
                case FirewallDataType.Empty:
                    return new FirewallEmpty();
                default:
                    Console.WriteLine("Unhandled type: {0}", type);
                    return type.ToString();
            }
        }

        internal FirewallValue(FWP_VALUE0 value, Guid condition_key)
        {
            Type = value.type;
            Value = ToObject(value.type, value.value, condition_key);
            ContextValue = SpecializeValue(value.type, Value, condition_key);
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The value as a string.</returns>
        public override string ToString()
        {
            return ContextValue?.ToString() ?? "(null)";
        }
    }
}
