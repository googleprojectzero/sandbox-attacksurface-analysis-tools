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
using System.Text;
using System.Threading.Tasks;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Server
{
    internal static class KerberosKDCServerUtils
    {
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

        internal static async Task<string> ReadLineAsync(this Stream stm, int maximum_length = 8*1024)
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
