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
using System.IO;

namespace NtApiDotNet.Net
{
    internal static class NetUtils
    {
        internal static byte[] SwapEndian(this byte[] ba)
        {
            if (BitConverter.IsLittleEndian)
            {
                byte[] ret = new byte[ba.Length];
                for (int i = 0; i < ret.Length; ++i)
                {
                    ret[i] = ba[ba.Length - i - 1];
                }
                return ret;
            }

            return ba;
        }

        internal static ushort SwapEndian(this ushort value)
        {
            return BitConverter.ToUInt16(BitConverter.GetBytes(value).SwapEndian(), 0);
        }

        internal static int SwapEndian(this int value)
        {
            return BitConverter.ToInt32(BitConverter.GetBytes(value).SwapEndian(), 0);
        }

        internal static uint SwapEndian(this uint value)
        {
            return BitConverter.ToUInt32(BitConverter.GetBytes(value).SwapEndian(), 0);
        }

        internal static long SwapEndian(this long value)
        {
            return BitConverter.ToInt64(BitConverter.GetBytes(value).SwapEndian(), 0);
        }

        internal static ushort ReadUInt16BE(this BinaryReader reader)
        {
            return reader.ReadUInt16().SwapEndian();
        }

        internal static void WriteInt32BE(this BinaryWriter writer, int value)
        {
            writer.Write(value.SwapEndian());
        }

        internal static void WriteUInt32BE(this BinaryWriter writer, uint value)
        {
            writer.Write(value.SwapEndian());
        }

        internal static void WriteUInt16BE(this BinaryWriter writer, int value)
        {
            writer.Write(((ushort)value).SwapEndian());
        }

        internal static int ReadInt32BE(this BinaryReader reader)
        {
            return reader.ReadInt32().SwapEndian();
        }

        internal static uint ReadUInt32BE(this BinaryReader reader)
        {
            return reader.ReadUInt32().SwapEndian();
        }
    }
}
