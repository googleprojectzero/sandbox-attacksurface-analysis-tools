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

using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace NtCoreLib.Utilities.ASN1;

internal static class DERUtils
{
    public static int ReadLength(this BinaryReader reader)
    {
        int length = reader.ReadByte();
        if ((length & 0x80) == 0)
            return length;

        int count = length & 0x7F;
        length = 0;
        for (int i = 0; i < count; ++i)
        {
            length <<= 8;
            length |= reader.ReadByte();
        }
        return length;
    }

    public static int ReadEncodedInt(this BinaryReader reader)
    {
        int value = 0;
        while (true)
        {
            byte next = reader.ReadByte();
            value <<= 7;
            value |= next & 0x7F;
            if ((next & 0x80) == 0)
                break;
        }
        return value;
    }

    public static long RemainingLength(this BinaryReader reader)
    {
        return reader.BaseStream.Length - reader.BaseStream.Position;
    }

    public static string ReadObjID(byte[] data)
    {
        List<int> values = new();
        BinaryReader reader = new(new MemoryStream(data));
        byte first = reader.ReadByte();
        values.Add(first / 40);
        values.Add(first % 40);
        while (reader.RemainingLength() > 0)
        {
            values.Add(reader.ReadEncodedInt());
        }
        return string.Join(".", values);
    }

    public static bool CheckValueSequence(this DERValue[] values)
    {
        if (values.Length != 1 || !values[0].CheckSequence() || !values[0].HasChildren())
            return false;
        return true;
    }

    public static bool TryParseGeneralizedTime(string time_str, out DateTime time)
    {
        return DateTime.TryParseExact(time_str, "yyyyMMddHHmmssZ",
            CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out time);
    }

    public static DateTime ParseGeneralizedTime(string time_str)
    {
        if (!TryParseGeneralizedTime(time_str, out DateTime time))
        {
            throw new FormatException("Invalid generalized time string.");
        }
        return time;
    }

    public static string ConvertGeneralizedTime(DateTime time)
    {
        return time.ToUniversalTime().ToString("yyyyMMddHHmmssZ");
    }

    public static BitArray ReadBitString(byte[] data)
    {
        if (data.Length == 0)
            return new BitArray(0);
        IEnumerable<bool> bools = data.Skip(1).SelectMany(b => GetBool(b));
        int total_count = (data.Length - 1) * 8 - data[0];
        return new BitArray(bools.Take(total_count).ToArray());
    }

    private static IEnumerable<bool> GetBool(byte b)
    {
        bool[] ret = new bool[8];
        for (int i = 0; i < 8; ++i)
        {
            ret[i] = ((b >> (7 - i)) & 1) != 0;
        }
        return ret;
    }
}
