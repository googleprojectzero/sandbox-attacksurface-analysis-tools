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
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NtCoreLib.Utilities.ASN1.Builder;

/// <summary>
/// Static class for DER builder utility functions.
/// </summary>
internal static class DERBuilderUtils
{
    public static byte[] EncodeLength(int value)
    {
        if (value < 0)
            throw new ArgumentOutOfRangeException("Invalid length value. Can't be negative.", nameof(value));
        if (value < 0x80)
            return new byte[] { (byte)value };
        if (value < 0x100)
            return new byte[] { 0x81, (byte)value };
        if (value < 0x10000)
            return new byte[] { 0x82, (byte)(value >> 8), (byte)(value & 0xFF) };
        if (value < 0x1000000)
            return new byte[] { 0x83, (byte)(value >> 16), (byte)(value >> 8), (byte)(value & 0xFF) };
        return new byte[] { 0x84, (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)(value & 0xFF) };
    }

    public static void WriteEncodedInt(this BinaryWriter writer, int value)
    {
        if (value < 0)
            throw new ArgumentOutOfRangeException("Invalid length value. Can't be negative.", nameof(value));

        List<byte> encoded_int = new();
        encoded_int.Add((byte)(value & 0x7F));
        value >>= 7;
        while (value != 0)
        {
            encoded_int.Insert(0, (byte)((value & 0x7F) | 0x80));
            value >>= 7;
        }

        writer.Write(encoded_int.ToArray());
    }

    public static void WriteLength(this BinaryWriter writer, int length)
    {
        writer.Write(EncodeLength(length));
    }

    public static void WriteTaggedValue(this BinaryWriter writer, DERTagType tag_type, bool constructed, int tag, byte[] data)
    {
        if (data is null)
        {
            throw new ArgumentNullException(nameof(data));
        }

        int id = ((int)tag_type << 6);
        if (constructed)
            id |= 0x20;
        if (tag < 0x1F)
        {
            writer.WriteByte(id | tag);
        }
        else
        {
            writer.WriteByte(id | 0x1F);
            writer.WriteEncodedInt(tag);
        }
        writer.WriteLength(data.Length);
        writer.Write(data);
    }

    public static void WriteUniversalValue(this BinaryWriter writer, bool constructed, UniversalTag tag, byte[] data)
    {
        WriteTaggedValue(writer, DERTagType.Universal, constructed, (int)tag, data);
    }

    public static void WriteUniversalValue(this BinaryWriter writer, bool constructed, UniversalTag tag, Action<BinaryWriter> data_builder)
    {
        MemoryStream stm = new();
        data_builder(new BinaryWriter(stm));

        WriteTaggedValue(writer, DERTagType.Universal, constructed, (int)tag, stm.ToArray());
    }

    public static void WriteByte(this BinaryWriter writer, long value)
    {
        if (value < 0 || value > byte.MaxValue)
            throw new ArgumentOutOfRangeException("Value too large for a byte.", nameof(value));
        writer.Write((byte)value);
    }

    public static void WriteObjectId(this BinaryWriter writer, int[] values)
    {
        writer.WriteByte(values[0] * 40 + values[1]);
        foreach (var value in values.Skip(2))
        {
            writer.WriteEncodedInt(value);
        }
    }
}
