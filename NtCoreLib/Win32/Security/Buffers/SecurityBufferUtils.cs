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

using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Buffers
{
    /// <summary>
    /// Utilities for security buffers.
    /// </summary>
    public static class SecurityBufferUtils
    {
        /// <summary>
        /// Convert a list of data buffers to a byte array.
        /// </summary>
        /// <param name="buffers">List of data security buffers. Only buffers used for input are processed.</param>
        /// <returns>The data buffers as one bytes array.</returns>
        public static byte[] ToByteArray(this IEnumerable<SecurityBuffer> buffers)
        {
            return ToByteArray(buffers.Where(b => b.Type == SecurityBufferType.Data).OfType<ISecurityBufferIn>());
        }

        /// <summary>
        /// Update a list of data buffers with known data.
        /// </summary>
        /// <param name="buffers">The buffers to update.</param>
        /// <param name="data">The data to update with.</param>
        public static void UpdateDataBuffers(this IEnumerable<SecurityBuffer> buffers, byte[] data)
        {
            UpdateDataBuffers(buffers.Where(b => b.Type == SecurityBufferType.Data && !b.ReadOnly).OfType<ISecurityBufferOut>(), data);
        }

        internal static void UpdateDataBuffers(this IEnumerable<ISecurityBufferOut> buffers, byte[] data)
        {
            MemoryStream stm = new MemoryStream(data);
            BinaryReader reader = new BinaryReader(stm);
            foreach (var buffer in buffers)
            {
                buffer.Update(SecurityBufferType.Data, reader.ReadAllBytes(buffer.Size));
            }
        }

        internal static byte[] ToByteArray(this IEnumerable<ISecurityBufferIn> buffers)
        {
            MemoryStream stm = new MemoryStream();
            foreach (var buffer in buffers)
            {
                byte[] ba = buffer.ToArray();
                stm.Write(ba, 0, ba.Length);
            }
            return stm.ToArray();
        }
    }
}
