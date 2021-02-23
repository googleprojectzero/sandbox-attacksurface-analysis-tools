//  Copyright 2021 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Win32.Security.Native;
using System.Collections.Generic;

namespace NtApiDotNet.Win32.Security.Buffers
{
    /// <summary>
    /// Base security buffer storage.
    /// </summary>
    public abstract class SecurityBuffer
    {
        private protected SecurityBufferType _type;

        /// <summary>
        /// Type of the security buffer.
        /// </summary>
        public SecurityBufferType Type => _type & SecurityBufferType.Mask;

        /// <summary>
        /// Is the buffer read-only.
        /// </summary>
        public bool ReadOnly => _type.HasFlagSet(SecurityBufferType.ReadOnly) || WithChecksum;

        /// <summary>
        /// Is the buffer read-only with checksum.
        /// </summary>
        public bool WithChecksum => _type.HasFlagSet(SecurityBufferType.ReadOnlyWithChecksum);

        /// <summary>
        /// Convert to buffer back to an array.
        /// </summary>
        /// <returns>The buffer as an array.</returns>
        public abstract byte[] ToArray();

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The buffer as a string.</returns>
        public override string ToString()
        {
            List<SecurityBufferType> types = new List<SecurityBufferType>
            {
                Type
            };
            if (WithChecksum)
            {
                types.Add(SecurityBufferType.ReadOnlyWithChecksum);
            }
            else if (ReadOnly)
            {
                types.Add(SecurityBufferType.ReadOnly);
            }

            return $"Buffer Type: {string.Join(",", types)}";
        }

        internal abstract void FromBuffer(SecBuffer buffer);
        internal abstract SecBuffer ToBuffer();

        private protected SecurityBuffer(SecurityBufferType type)
        {
            _type = type;
        }
    }
}
