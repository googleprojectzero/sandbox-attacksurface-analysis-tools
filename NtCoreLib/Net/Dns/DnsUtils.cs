//  Copyright 2022 Google LLC. All Rights Reserved.
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
using System.Text;

namespace NtCoreLib.Net.Dns;

internal static class DnsUtils
{
    private static void WriteStringPart(this BinaryWriter writer, string value, Dictionary<string, int> string_cache)
    {
        if (string.IsNullOrEmpty(value) || (value == "."))
        {
            writer.WriteByte(0);
        }
        else
        {
            if (string_cache?.ContainsKey(value) ?? false)
            {
                writer.WriteUInt16BE(0xC000 | string_cache[value]);
            }
            else
            {
                string[] values = value.Split(new[] { '.' }, 2, StringSplitOptions.RemoveEmptyEntries);

                if (values[0].Length > 63)
                {
                    throw new InvalidDataException("DNS names components cannot be longer than 63 characters");
                }

                long pos = writer.BaseStream.Position;
                writer.WriteByte(values[0].Length & 0x3F);
                writer.WriteBinaryString(values[0]);
                string_cache?.Add(value, (int)pos);

                if (values.Length > 1)
                {
                    writer.WriteStringPart(values[1], string_cache);
                }
                else
                {
                    writer.WriteStringPart(null, string_cache);
                }
            }
        }
    }

    internal static void WriteDnsString(this BinaryWriter writer, string value, Dictionary<string, int> stringCache)
    {
        value = value.TrimEnd().TrimEnd('.');

        writer.WriteStringPart(value, stringCache);
    }

    internal static string ReadDnsString(this BinaryReader reader, byte[] data)
    {
        StringBuilder name = new();
        int len = reader.ReadByte();

        while (len != 0)
        {
            if ((len & 0xC0) != 0)
            {
                int ofs = (len & ~0xC0) << 8;

                ofs |= reader.ReadByte();

                MemoryStream stm = new(data)
                {
                    Position = ofs
                };

                name.Append(new BinaryReader(stm).ReadDnsString(data));

                break;
            }
            else
            {
                name.Append(reader.ReadBinaryString(len)).Append(".");
            }

            len = reader.ReadByte();
        }

        return name.ToString();
    }
}
