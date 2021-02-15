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
    /// Class to represent an empty security buffer.
    /// </summary>
    public class SecurityBufferEmpty : SecurityBuffer
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="type">The type of buffer.</param>
        public SecurityBufferEmpty(SecurityBufferType type) 
            : base(type)
        {
        }

        /// <summary>
        /// Convert to buffer back to an array.
        /// </summary>
        /// <returns>The buffer as an array.</returns>
        public override byte[] ToArray()
        {
            return new byte[0];
        }

        internal override void FromBuffer(SecBuffer buffer)
        {
        }

        internal override SecBuffer ToBuffer()
        {
            return new SecBuffer { BufferType = Type };
        }
    }
}
