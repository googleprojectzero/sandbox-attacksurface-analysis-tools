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
using System.Linq;

namespace NtApiDotNet.Utilities.Security
{
    /// <summary>
    /// Basic implementation of ARC4.
    /// </summary>
    public static class ARC4
    {
        private static void Swap(byte[] s, int i, int j)
        {
            byte x = s[i];
            s[i] = s[j];
            s[j] = x;
        }

        private static byte[] CreateKeySchedule(byte[] key)
        {
            byte[] s = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
            int j = 0;
            for (int i = 0; i < 256; ++i)
            {
                j = (j + s[i] + key[i % key.Length]) & 0xFF;
                Swap(s, i, j);
            }
            return s;
        }

        /// <summary>
        /// Encrypt, or decrypt an ARC4 stream.
        /// </summary>
        /// <param name="data">The data to encrypt/decrypt.</param>
        /// <param name="offset">Offset into the data to decrypt.</param>
        /// <param name="length">Length of data to decrypt.</param>
        /// <param name="key">The key to decrypt.</param>
        /// <returns>The resulting bytes.</returns>
        public static byte[] Transform(byte[] data, int offset, int length, byte[] key)
        {
            byte[] s = CreateKeySchedule(key);
            byte[] ret = new byte[length];
            Buffer.BlockCopy(data, offset, ret, 0, length);

            int i = 0;
            int j = 0;
            int p = 0;
            while (p < length)
            {
                i = (i + 1) & 0xFF;
                j = (j + s[i]) & 0xFF;
                Swap(s, i, j);
                byte k = s[(s[i] + s[j]) & 0xFF];
                ret[p] ^= k;
                p++;
            }
            return ret;
        }

        /// <summary>
        /// Encrypt, or decrypt an ARC4 stream.
        /// </summary>
        /// <param name="data">The data to encrypt/decrypt.</param>
        /// <param name="key">The key to decrypt.</param>
        /// <returns>The resulting bytes.</returns>
        public static byte[] Transform(byte[] data, byte[] key)
        {
            return Transform(data, 0, data.Length, key);
        }
    }
}
