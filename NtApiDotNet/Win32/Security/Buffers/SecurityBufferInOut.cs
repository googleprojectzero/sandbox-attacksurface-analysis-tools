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
using System;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Buffers
{
    /// <summary>
    /// A security buffer which can be an input and output.
    /// </summary>
    /// <remarks>If you create with the ReadOnly or ReadOnlyWithCheck types then the 
    /// array will not be updated.</remarks>
    public class SecurityBufferInOut : SecurityBuffer
    {
        private ArraySegment<byte> _array;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="type">The type of buffer.</param>
        /// <param name="data">The data for the input.</param>
        public SecurityBufferInOut(SecurityBufferType type, byte[] data) : base(type)
        {
            _array = new ArraySegment<byte>(data);
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="type">The type of buffer.</param>
        /// <param name="data">The data for the input.</param>
        /// <param name="offset">The offset into the array.</param>
        /// <param name="count">Number of bytes in the input.</param>
        public SecurityBufferInOut(SecurityBufferType type, byte[] data, int offset, int count) : base(type)
        {
            _array = new ArraySegment<byte>(data, offset, count);
        }

        /// <summary>
        /// Convert to buffer back to an array.
        /// </summary>
        /// <returns>The buffer as an array.</returns>
        public override byte[] ToArray()
        {
            return _array.ToArray();
        }

        internal override SecBuffer ToBuffer()
        {
            return new SecBuffer(Type, ToArray());
        }

        internal override void FromBuffer(SecBuffer buffer)
        {
            if (Type.HasFlagSet(SecurityBufferType.ReadOnly | SecurityBufferType.ReadOnlyWithChecksum))
            {
                return;
            }
            _array = new ArraySegment<byte>(buffer.ToArray());
        }
    }
}
