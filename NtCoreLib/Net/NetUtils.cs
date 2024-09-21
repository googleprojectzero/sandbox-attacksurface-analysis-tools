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
using System.IO;
using System.Text;
using System.Threading.Tasks;

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

        internal static void WriteBinaryString(this BinaryWriter writer, string str)
        {
            writer.Write(BinaryEncoding.Instance.GetBytes(str));
        }

        internal static string ReadBinaryString(this BinaryReader reader, int length)
        {
            return BinaryEncoding.Instance.GetString(reader.ReadAllBytes(length));
        }

        internal static void WriteByte(this BinaryWriter writer, int value)
        {
            writer.Write((byte)value);
        }

        internal static void WriteUInt16(this BinaryWriter writer, int value)
        {
            writer.Write((ushort)value);
        }

        internal static async Task<byte[]> ReadBytesAsync(this Stream stm, int length)
        {
            byte[] ret = new byte[length];
            int count = 0;
            while (count < length)
            {
                var result = await stm.ReadAsync(ret, count, length - count);
                if (result <= 0)
                    throw new EndOfStreamException();
                count += result;
            }
            return ret;
        }

        internal static async Task<int> ReadInt32Async(this Stream stm)
        {
            return BitConverter.ToInt32(await ReadBytesAsync(stm, 4), 0).SwapEndian();
        }

        internal static async Task WriteBytesAsync(this Stream stm, byte[] data)
        {
            await stm.WriteAsync(data, 0, data.Length);
        }

        internal static async Task WriteInt32Async(this Stream stm, int value)
        {
            await stm.WriteBytesAsync(BitConverter.GetBytes(value.SwapEndian()));
        }

        internal static async Task<char> ReadCharAsync(this Stream stm)
        {
            byte[] ret = await stm.ReadBytesAsync(1);
            return (char)ret[0];
        }

        internal static async Task<string> ReadLineAsync(this Stream stm, int maximum_length = 8 * 1024)
        {
            StringBuilder builder = new StringBuilder();
            do
            {
                if (builder.Length > maximum_length)
                    throw new InvalidDataException("Header length too large.");
                char ch = await stm.ReadCharAsync();
                if (ch == '\n')
                    break;
                builder.Append(ch);
            }
            while (true);
            return builder.ToString().TrimEnd();
        }

        internal static async Task WriteLineAsync(this Stream stm, string line)
        {
            byte[] data = Encoding.ASCII.GetBytes(line + "\r\n");
            await stm.WriteAsync(data, 0, data.Length);
        }
    }
}
