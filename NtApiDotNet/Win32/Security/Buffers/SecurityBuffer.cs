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

namespace NtApiDotNet.Win32.Security.Buffers
{
    /// <summary>
    /// Base security buffer storage.
    /// </summary>
    public abstract class SecurityBuffer
    {
        /// <summary>
        /// Type of the security buffer.
        /// </summary>
        public SecurityBufferType Type { get; }

        /// <summary>
        /// Convert to buffer back to an array.
        /// </summary>
        /// <returns>The buffer as an array.</returns>
        public abstract byte[] ToArray();

        internal abstract void FromBuffer(SecBuffer buffer);
        internal abstract SecBuffer ToBuffer();

        private protected SecurityBuffer(SecurityBufferType type)
        {
            Type = type;
        }
    }
}
