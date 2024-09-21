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

// Original license from RFC1320 of which this is a derived work.
/* Copyright (C) 1990-2, RSA Data Security, Inc. All rights reserved.

   License to copy and use this software is granted provided that it
   is identified as the "RSA Data Security, Inc. MD4 Message-Digest
   Algorithm" in all material mentioning or referencing this software
   or this function.

   License is also granted to make and use derivative works provided
   that such works are identified as "derived from the RSA Data
   Security, Inc. MD4 Message-Digest Algorithm" in all material
   mentioning or referencing the derived work.

   RSA Data Security, Inc. makes no representations concerning either
   the merchantability of this software or the suitability of this
   software for any particular purpose. It is provided "as is"
   without express or implied warranty of any kind.

   These notices must be retained in any copies of any part of this
   documentation and/or software.
 */

using System;
using System.IO;
using System.Text;

namespace NtApiDotNet.Utilities.Security
{
    /// <summary>
    /// Basic implementation of MD4.
    /// </summary>
    /// <remarks>
    /// This could have called out to the CNG APIs or dug into the
    /// internals of the existing .NET crypto APIs but as MD4 is so
    /// simple and it doesn't need to be secure (seriously don't use
    /// this). This uses the reference implementation from RFC1320.
    /// </remarks>
    public static class MD4
    {
        #region Private Members
        private static uint F(uint x, uint y, uint z)
        {
            return (x & y) | (~x & z);
        }

        private static uint G(uint x, uint y, uint z)
        {
            return (x & y) | (x & z) | (y & z);
        }

        private static uint H(uint x, uint y, uint z)
        {
            return x ^ y ^ z;
        }

        private static uint RotateLeft(uint x, int n)
        {
            return (x << n) | (x >> (32 - n));
        }

        private static void FF(ref uint a, uint b, uint c, uint d, uint x, int s)
        {
            a += F(b, c, d) + x;
            a = RotateLeft(a, s);
        }

        private static void GG(ref uint a, uint b, uint c, uint d, uint x, int s)
        {
            a += G(b, c, d) + x + 0x5A827999U;
            a = RotateLeft(a, s);
        }

        private static void HH(ref uint a, uint b, uint c, uint d, uint x, int s)
        {
            a += H(b, c, d) + x + 0x6ED9EBA1U;
            a = RotateLeft(a, s);
        }

        private const int S11 = 3;
        private const int S12 = 7;
        private const int S13 = 11;
        private const int S14 = 19;
        private const int S21 = 3;
        private const int S22 = 5;
        private const int S23 = 9;
        private const int S24 = 13;
        private const int S31 = 3;
        private const int S32 = 9;
        private const int S33 = 11;
        private const int S34 = 15;

        private static void MD4Transform(uint[] state, byte[] block)
        {
            System.Diagnostics.Debug.Assert(state.Length == 4);
            System.Diagnostics.Debug.Assert(block.Length == 64);
            uint a = state[0], b = state[1], c = state[2], d = state[3];
            uint[] x = new uint[16];
            Buffer.BlockCopy(block, 0, x, 0, 64);
            /* Round 1 */
            FF(ref a, b, c, d, x[0], S11); /* 1 */
            FF(ref d, a, b, c, x[1], S12); /* 2 */
            FF(ref c, d, a, b, x[2], S13); /* 3 */
            FF(ref b, c, d, a, x[3], S14); /* 4 */
            FF(ref a, b, c, d, x[4], S11); /* 5 */
            FF(ref d, a, b, c, x[5], S12); /* 6 */
            FF(ref c, d, a, b, x[6], S13); /* 7 */
            FF(ref b, c, d, a, x[7], S14); /* 8 */
            FF(ref a, b, c, d, x[8], S11); /* 9 */
            FF(ref d, a, b, c, x[9], S12); /* 10 */
            FF(ref c, d, a, b, x[10], S13); /* 11 */
            FF(ref b, c, d, a, x[11], S14); /* 12 */
            FF(ref a, b, c, d, x[12], S11); /* 13 */
            FF(ref d, a, b, c, x[13], S12); /* 14 */
            FF(ref c, d, a, b, x[14], S13); /* 15 */
            FF(ref b, c, d, a, x[15], S14); /* 16 */

            /* Round 2 */
            GG(ref a, b, c, d, x[0], S21); /* 17 */
            GG(ref d, a, b, c, x[4], S22); /* 18 */
            GG(ref c, d, a, b, x[8], S23); /* 19 */
            GG(ref b, c, d, a, x[12], S24); /* 20 */
            GG(ref a, b, c, d, x[1], S21); /* 21 */
            GG(ref d, a, b, c, x[5], S22); /* 22 */
            GG(ref c, d, a, b, x[9], S23); /* 23 */
            GG(ref b, c, d, a, x[13], S24); /* 24 */
            GG(ref a, b, c, d, x[2], S21); /* 25 */
            GG(ref d, a, b, c, x[6], S22); /* 26 */
            GG(ref c, d, a, b, x[10], S23); /* 27 */
            GG(ref b, c, d, a, x[14], S24); /* 28 */
            GG(ref a, b, c, d, x[3], S21); /* 29 */
            GG(ref d, a, b, c, x[7], S22); /* 30 */
            GG(ref c, d, a, b, x[11], S23); /* 31 */
            GG(ref b, c, d, a, x[15], S24); /* 32 */

            /* Round 3 */
            HH(ref a, b, c, d, x[0], S31); /* 33 */
            HH(ref d, a, b, c, x[8], S32); /* 34 */
            HH(ref c, d, a, b, x[4], S33); /* 35 */
            HH(ref b, c, d, a, x[12], S34); /* 36 */
            HH(ref a, b, c, d, x[2], S31); /* 37 */
            HH(ref d, a, b, c, x[10], S32); /* 38 */
            HH(ref c, d, a, b, x[6], S33); /* 39 */
            HH(ref b, c, d, a, x[14], S34); /* 40 */
            HH(ref a, b, c, d, x[1], S31); /* 41 */
            HH(ref d, a, b, c, x[9], S32); /* 42 */
            HH(ref c, d, a, b, x[5], S33); /* 43 */
            HH(ref b, c, d, a, x[13], S34); /* 44 */
            HH(ref a, b, c, d, x[3], S31); /* 45 */
            HH(ref d, a, b, c, x[11], S32); /* 46 */
            HH(ref c, d, a, b, x[7], S33); /* 47 */
            HH(ref b, c, d, a, x[15], S34); /* 48 */

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
        }
        #endregion

        #region Public Static Methods
        /// <summary>
        /// Calculate the MD4 hash of an input.
        /// </summary>
        /// <param name="input">The input bytes.</param>
        /// <returns>The MD4 hash.</returns>
        public static byte[] CalculateHash(byte[] input)
        {
            if (!BitConverter.IsLittleEndian)
                throw new ArgumentException("Only works on Little Endian systems");
            uint[] state = new uint[] { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };

            int remaining = input.Length % 64;
            int pad_len = (remaining < 56) ? (56 - remaining) : (120 - remaining);
            MemoryStream stm = new MemoryStream();
            stm.Write(input, 0, input.Length);
            stm.WriteByte(0x80);
            stm.Write(new byte[pad_len - 1], 0, pad_len - 1);
            stm.Write(BitConverter.GetBytes(input.LongLength * 8), 0, 8);

            System.Diagnostics.Debug.Assert((stm.Length % 64) == 0);

            stm.Position = 0;
            BinaryReader reader = new BinaryReader(stm);

            while (reader.BaseStream.Position < reader.BaseStream.Length)
            {
                byte[] block = reader.ReadBytes(64);
                MD4Transform(state, block);
            }

            byte[] ret = new byte[16];
            Buffer.BlockCopy(state, 0, ret, 0, 16);
            return ret;
        }

        /// <summary>
        /// Calculate the MD4 hash of a string.
        /// </summary>
        /// <param name="input">The input string.</param>
        /// <param name="encoding">Encoding for the string.</param>
        /// <returns>The MD4 hash.</returns>
        public static byte[] CalculateHash(string input, Encoding encoding)
        {
            if (encoding == null)
            {
                encoding = Encoding.Unicode;
            }
            return CalculateHash(encoding.GetBytes(input));
        }

        /// <summary>
        /// Calculate the MD4 hash of a unicode string.
        /// </summary>
        /// <param name="input">The input string.</param>
        /// <returns>The MD4 hash.</returns>
        public static byte[] CalculateHash(string input)
        {
            return CalculateHash(input, Encoding.Unicode);
        }
        #endregion
    }
}
