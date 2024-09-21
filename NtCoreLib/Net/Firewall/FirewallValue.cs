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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Utilities.Collections;
using NtCoreLib.Utilities.Memory;
using NtCoreLib.Win32.Rpc.Transport;
using System;
using System.Collections;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace NtCoreLib.Net.Firewall;

/// <summary>
/// Firewall value.
/// </summary>
public struct FirewallValue : IComparable<FirewallValue>, IComparable, ICloneable
{
    #region Public Properties
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
    #endregion

    #region Private Members
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
        else if (FirewallConditionGuids.IsAppId(condition_key) ||
            condition_key == FirewallConditionGuids.FWPM_CONDITION_PIPE ||
            condition_key == FirewallConditionGuids.FWPM_CONDITION_RPC_SERVER_NAME)
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
        else if (type == FirewallDataType.Sid)
        {
            if (value is Sid sid)
            {
                return sid.Name;
            }
        }
        else if (type is FirewallDataType.SecurityDescriptor && value is SecurityDescriptor sd)
        {
            if (sd.DaclPresent && sd.Dacl.Count == 1
                && sd.Dacl[0].Type == AceType.Allowed
                && sd.Dacl[0].Mask.IsAccessGranted(FirewallFilterAccessRights.Match))
            {
                return sd.Dacl[0].Sid.Name;
            }
            return sd.ToSddl();
        }
        else if (condition_key == FirewallConditionGuids.FWPM_CONDITION_DIRECTION)
        {
            if (value is uint ui)
            {
                return (FirewallDirectionType)ui;
            }
        }
        else if (condition_key == FirewallConditionGuids.FWPM_CONDITION_RPC_AUTH_TYPE)
        {
            if (value is byte b)
            {
                return (RpcAuthenticationType)b;
            }
        }
        else if (condition_key == FirewallConditionGuids.FWPM_CONDITION_RPC_AUTH_LEVEL)
        {
            if (value is byte b)
            {
                return (RpcAuthenticationType)b;
            }
        }
        else if (FirewallConditionGuids.IsMacAddressCondition(condition_key))
        {
            if (value is byte[] ba && ba.Length == 6)
            {
                return string.Join(":", ba.Select(b => $"{b:X02}"));
            }
        }
        else if (FirewallConditionGuids.IsProfileId(condition_key))
        {
            if (value is uint profile_id)
            {
                return (FirewallProfileId)profile_id;
            }
        }
        else if (FirewallConditionGuids.IsDataLink(condition_key))
        {
            if (value is byte dl_type)
            {
                return (DataLinkAddressType)dl_type;
            }
        }
        else if (FirewallConditionGuids.IsNetworkLayer(condition_key))
        {
            if (value is byte nl_type)
            {
                return (NetworkLayerAddressType)nl_type;
            }
        }
        else if (FirewallConditionGuids.IsTunnelType(condition_key))
        {
            if (value is uint tunnel_type)
            {
                return (NetworkTunnelType)tunnel_type;
            }
        }
        else if (FirewallConditionGuids.IsInterfaceType(condition_key))
        {
            if (value is uint if_type)
            {
                return (NetworkInterfaceType)if_type;
            }
        }

        return value;
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
        var blob = ptr.ReadStruct<FWP_BYTE_BLOB>();
        return ReadBytes(blob.data, blob.size);
    }

    private static object ToObject(FirewallDataType type, FWP_VALUE0_UNION value, Guid condition_key)
    {
        return type switch
        {
            FirewallDataType.SecurityDescriptor => SecurityDescriptor.Parse(ReadBlob(value.sd), FirewallUtils.FirewallFilterType, false).GetResultOrDefault(),
            FirewallDataType.TokenInformation => new FirewallTokenInformation(value.tokenInformation.ReadStruct<FWP_TOKEN_INFORMATION>()),
            FirewallDataType.TokenAccessInformation => ReadBlob(value.tokenAccessInformation),
            FirewallDataType.Sid => Sid.Parse(value.sid, false).GetResultOrDefault(),
            FirewallDataType.UInt8 => value.uint8,
            FirewallDataType.UInt16 => value.uint16,
            FirewallDataType.UInt32 => value.uint32,
            FirewallDataType.Int8 => value.int8,
            FirewallDataType.Int16 => value.int16,
            FirewallDataType.Int32 => value.int32,
            FirewallDataType.Range => new FirewallRange(value.rangeValue.ReadStruct<FWP_RANGE0>(), condition_key),
            FirewallDataType.ByteArray16 => ReadBytes(value.byteArray16, 16),
            FirewallDataType.ByteArray6 => ReadBytes(value.byteArray6, 6),
            FirewallDataType.UInt64 => (ulong)Marshal.ReadInt64(value.uint64),
            FirewallDataType.Int64 => Marshal.ReadInt64(value.uint64),
            FirewallDataType.ByteBlob => ReadBlob(value.byteBlob),
            FirewallDataType.V4AddrMask => new FirewallAddressAndMask(value.v4AddrMask.ReadStruct<FWP_V4_ADDR_AND_MASK>()),
            FirewallDataType.V6AddrMask => new FirewallAddressAndMask(value.v6AddrMask.ReadStruct<FWP_V6_ADDR_AND_MASK>()),
            FirewallDataType.UnicodeString => Marshal.PtrToStringUni(value.unicodeString),
            FirewallDataType.BitmapArray64 => new BitArray(value.bitmapArray64.ReadStruct<FWP_BITMAP_ARRAY64>().bitmapArray64),
            FirewallDataType.Empty => new FirewallEmpty(),
            _ => type.ToString(),
        };
    }

    #endregion

    #region Internal Members
    internal FirewallValue(FWP_VALUE0 value, Guid condition_key)
    {
        Type = value.type;
        Value = ToObject(value.type, value.value, condition_key);
        ContextValue = SpecializeValue(value.type, Value, condition_key);
    }

    internal FirewallValue(FirewallDataType type, object value, object context_value)
    {
        Type = type;
        Value = value;
        ContextValue = context_value;
    }

    internal FirewallValue(FirewallDataType type, object value) 
        : this(type, value, value)
    {
    }

    internal FWP_VALUE0 ToStruct(DisposableList list)
    {
        FWP_VALUE0 ret = new();
        switch (Type)
        {
            case FirewallDataType.Empty:
                break;
            case FirewallDataType.Sid:
                ret.value.sid = list.AddSid((Sid)Value).DangerousGetHandle();
                break;
            case FirewallDataType.UInt8:
                ret.value.uint8 = ((IConvertible)Value).ToByte(null);
                break;
            case FirewallDataType.UInt16:
                ret.value.uint16 = ((IConvertible)Value).ToUInt16(null);
                break;
            case FirewallDataType.UInt32:
                ret.value.uint32 = ((IConvertible)Value).ToUInt32(null);
                break;
            case FirewallDataType.Int8:
                ret.value.int8 = ((IConvertible)Value).ToSByte(null);
                break;
            case FirewallDataType.Int16:
                ret.value.int16 = ((IConvertible)Value).ToInt16(null);
                break;
            case FirewallDataType.Int32:
                ret.value.int32 = ((IConvertible)Value).ToInt32(null);
                break;
            case FirewallDataType.ByteArray16:
                ret.value.byteArray16 = list.AddResource(new SafeHGlobalBuffer((byte[])Value)).DangerousGetHandle();
                break;
            case FirewallDataType.ByteArray6:
                ret.value.byteArray6 = list.AddResource(new SafeHGlobalBuffer((byte[])Value)).DangerousGetHandle();
                break;
            case FirewallDataType.UInt64:
                ret.value.uint64 = list.AddResource(((IConvertible)Value).ToUInt64(null).ToBuffer()).DangerousGetHandle();
                break;
            case FirewallDataType.Int64:
                ret.value.int64 = list.AddResource(((IConvertible)Value).ToInt64(null).ToBuffer()).DangerousGetHandle();
                break;
            case FirewallDataType.TokenAccessInformation:
            case FirewallDataType.ByteBlob:
            case FirewallDataType.SecurityDescriptor:
            {
                    if (!(Value is byte[] buffer))
                    {
                        buffer = ((SecurityDescriptor)Value).ToByteArray();
                    }

                    FWP_BYTE_BLOB blob = new()
                    {
                        size = buffer.Length,
                        data = list.AddBytes(buffer).DangerousGetHandle()
                    };
                    ret.value.byteBlob = list.AddStructureRef(blob).DangerousGetHandle();
                    break;
                }
            case FirewallDataType.V4AddrMask:
                ret.value.v4AddrMask = ((FirewallAddressAndMask)Value).ToBuffer(list).DangerousGetHandle();
                break;
            case FirewallDataType.V6AddrMask:
                ret.value.v6AddrMask = ((FirewallAddressAndMask)Value).ToBuffer(list).DangerousGetHandle();
                break;
            case FirewallDataType.UnicodeString:
                ret.value.unicodeString = list.AddNulTerminatedUnicodeString((string)Value).DangerousGetHandle();
                break;
            case FirewallDataType.Range:
                ret.value.rangeValue = list.AddStructureRef(((FirewallRange)Value).ToStruct(list)).DangerousGetHandle();
                break;
            case FirewallDataType.TokenInformation:
                ret.value.tokenInformation = list.AddStructureRef(((FirewallTokenInformation)Value).ToStruct(list)).DangerousGetHandle();
                break;
            default:
                throw new ArgumentException($"Value type {Type} unsupported.");
        }
        ret.type = Type;
        return ret;
    }

    internal static FirewallValue FromBlob(byte[] value, object context_value)
    {
        return new FirewallValue(FirewallDataType.ByteBlob, value, context_value);
    }

    private static FirewallValue FromByteArray16(byte[] value, object context_value)
    {
        if (value.Length != 16)
            throw new ArgumentOutOfRangeException("Array must be 16 bytes in size.", nameof(value));
        return new FirewallValue(FirewallDataType.ByteArray16, value, context_value);
    }

    private static FirewallValue FromUInt32(uint value, object context_value)
    {
        return new FirewallValue(FirewallDataType.UInt32, value, context_value);
    }

    #endregion

    #region Static Members
    /// <summary>
    /// Get a value which represents Empty.
    /// </summary>
    public static FirewallValue Empty => new(FirewallDataType.Empty, new FirewallEmpty());

    /// <summary>
    /// Create a value from a security descriptor.
    /// </summary>
    /// <param name="security_descriptor">The security descriptor.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromSecurityDescriptor(SecurityDescriptor security_descriptor)
    {
        return new FirewallValue(FirewallDataType.SecurityDescriptor, security_descriptor);
    }

    /// <summary>
    /// Create a value from a SID.
    /// </summary>
    /// <param name="sid">The SID.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromSid(Sid sid)
    {
        return new FirewallValue(FirewallDataType.Sid, sid);
    }

    /// <summary>
    /// Create a value.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromUInt8(byte value)
    {
        return new FirewallValue(FirewallDataType.UInt8, value);
    }

    /// <summary>
    /// Create a value.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromUInt16(ushort value)
    {
        return new FirewallValue(FirewallDataType.UInt16, value);
    }

    /// <summary>
    /// Create a value.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromUInt32(uint value)
    {
        return new FirewallValue(FirewallDataType.UInt32, value);
    }

    /// <summary>
    /// Create a value.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromUInt64(ulong value)
    {
        return new FirewallValue(FirewallDataType.UInt64, value);
    }

    /// <summary>
    /// Create a value.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromUInt32Bool(bool value)
    {
        return FromUInt32(value ? 1U : 0U);
    }

    /// <summary>
    /// Create a value.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromInt8(sbyte value)
    {
        return new FirewallValue(FirewallDataType.Int8, value);
    }

    /// <summary>
    /// Create a value.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromInt16(short value)
    {
        return new FirewallValue(FirewallDataType.Int16, value);
    }

    /// <summary>
    /// Create a value.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromInt32(int value)
    {
        return new FirewallValue(FirewallDataType.Int32, value);
    }

    /// <summary>
    /// Create a value.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromInt64(ulong value)
    {
        return new FirewallValue(FirewallDataType.Int64, value);
    }

    /// <summary>
    /// Create a value.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromBlob(byte[] value)
    {
        return new FirewallValue(FirewallDataType.ByteBlob, value);
    }

    /// <summary>
    /// Create a value.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromBlobUnicodeString(string value)
    {
        return FromBlob(Encoding.Unicode.GetBytes(value + "\0"), value);
    }

    /// <summary>
    /// Create a value.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromUnicodeString(string value)
    {
        return new FirewallValue(FirewallDataType.UnicodeString, value);
    }

    /// <summary>
    /// Create a value.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromByteArray16(byte[] value)
    {
        if (value.Length != 16)
            throw new ArgumentOutOfRangeException("Array must be 16 bytes in size.", nameof(value));
        return new FirewallValue(FirewallDataType.ByteArray16, value);
    }

    /// <summary>
    /// Create a value.
    /// </summary>
    /// <param name="address">The IPv4 address.</param>
    /// <param name="mask">The IPv4 mask.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromV4AddrMask(IPAddress address, IPAddress mask)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new ArgumentException("Address must be InternetNetwork family.", nameof(address));
        }
        if (mask.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new ArgumentException("Mask must be InternetNetwork family.", nameof(mask));
        }
        return new FirewallValue(FirewallDataType.V4AddrMask, new FirewallAddressAndMask(address, mask));
    }

    /// <summary>
    /// Create a value.
    /// </summary>
    /// <param name="address">The IPv6 address.</param>
    /// <param name="prefix_length">The prefix length.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromV6AddrMask(IPAddress address, int prefix_length)
    {
        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            throw new ArgumentException("Address must be InterNetworkV6 family.", nameof(address));
        }
        if (prefix_length < 0 || prefix_length > 128)
        {
            throw new ArgumentOutOfRangeException("Prefix length invalid.", nameof(prefix_length));
        }
        return new FirewallValue(FirewallDataType.V6AddrMask, new FirewallAddressAndMask(address, prefix_length));
    }

    /// <summary>
    /// Create a value.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromProtocolType(ProtocolType value)
    {
        return new FirewallValue(FirewallDataType.UInt8, (byte)value, value);
    }

    /// <summary>
    /// Create a value.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromConditionFlags(FirewallConditionFlags value)
    {
        return new FirewallValue(FirewallDataType.UInt32, (uint)value, value);
    }

    /// <summary>
    /// Create a value.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromIpAddress(IPAddress value)
    {
        if (value.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return FromByteArray16(value.GetAddressBytes(), value);
        }
        else if (value.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] arr = value.GetAddressBytes();
            Array.Reverse(arr);
            return FromUInt32(BitConverter.ToUInt32(arr, 0), value);
        }
        throw new ArgumentException("Must specify V4 or V6 IP address.", nameof(value));
    }

    /// <summary>
    /// Create a range value.
    /// </summary>
    /// <param name="low">The low value.</param>
    /// <param name="high">The high value.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromRange(FirewallValue low, FirewallValue high)
    {
        return new FirewallValue(FirewallDataType.Range, new FirewallRange(low, high));
    }

    /// <summary>
    /// Create a value.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromTokenInformation(FirewallTokenInformation value)
    {
        return new FirewallValue(FirewallDataType.TokenInformation, value);
    }

    /// <summary>
    /// Create a value.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromTokenInformation(NtToken value)
    {
        return new FirewallValue(FirewallDataType.TokenInformation, 
            new FirewallTokenInformation(value));
    }

    /// <summary>
    /// Create a value.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromTokenAccessInformation(byte[] value)
    {
        return new FirewallValue(FirewallDataType.TokenAccessInformation, value);
    }

    /// <summary>
    /// Create a value.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The firewall value.</returns>
    public static FirewallValue FromGuid(Guid value)
    {
        return new FirewallValue(FirewallDataType.ByteArray16, value.ToByteArray(), value);
    }

    #endregion

    #region Public Methods
    /// <summary>
    /// Overridden ToString method.
    /// </summary>
    /// <returns>The value as a string.</returns>
    public override string ToString()
    {
        return ContextValue?.ToString() ?? "(null)";
    }
    #endregion

    #region Interface Implementations
    int IComparable<FirewallValue>.CompareTo(FirewallValue other)
    {
        if (Value is IComparable comp)
        {
            return comp.CompareTo(other.Value);
        }
        return 0;
    }

    int IComparable.CompareTo(object obj)
    {
        if (obj is FirewallValue other)
        {
            if (Value is IComparable comp)
            {
                return comp.CompareTo(other.Value);
            }
        }
        return 0;
    }

    object ICloneable.Clone()
    {
        return new FirewallValue(Type, Value.CloneValue(), ContextValue.CloneValue());
    }
    #endregion
}
