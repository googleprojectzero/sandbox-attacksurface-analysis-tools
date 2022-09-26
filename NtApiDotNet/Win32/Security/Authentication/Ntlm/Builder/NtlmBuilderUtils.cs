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

using NtApiDotNet.Utilities.Text;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Ntlm.Builder
{
    internal static class NtlmBuilderUtils
    {
        internal static void WriteVersion(this BinaryWriter writer, Version version)
        {
            if (version == null)
                version = new Version(0, 0, 0, 0);
            writer.Write((byte)version.Major);
            writer.Write((byte)version.Minor);
            writer.Write((ushort)version.Build);
            writer.Write(new byte[3]);
            writer.Write((byte)version.Revision);
        }

        internal static void WriteBinary(this BinaryWriter writer, byte[] data, int base_offset, MemoryStream payload)
        {
            data = data ?? Array.Empty<byte>();
            writer.Write((ushort)data.Length);
            writer.Write((ushort)data.Length);
            writer.Write((int)(base_offset + payload.Length));
            payload.Write(data, 0, data.Length);
        }

        internal static void WriteString(this BinaryWriter writer, string value, bool unicode, int base_offset, MemoryStream payload)
        {
            Encoding encoding = unicode ? Encoding.Unicode : BinaryEncoding.Instance;
            if (unicode && ((payload.Length % 2) != 0))
            {
                // Pad the payload for a unicode string.
                payload.WriteByte(0);
            }

            WriteBinary(writer, value != null ? encoding.GetBytes(value) : Array.Empty<byte>(), base_offset, payload);
        }

        internal static void SerializeAvPairs(this IReadOnlyCollection<NtlmAvPair> pairs, BinaryWriter writer)
        {
            foreach (var pair in pairs)
            {
                pair.Write(writer);
            }
            new NtlmAvPairBytes(MsAvPairType.EOL, Array.Empty<byte>()).Write(writer);
        }

        internal static byte[] SerializeAvPairs(this IReadOnlyCollection<NtlmAvPair> pairs)
        {
            if (pairs.Count == 0)
                return Array.Empty<byte>();
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            pairs.SerializeAvPairs(writer);
            return stm.ToArray();
        }
    }
}
