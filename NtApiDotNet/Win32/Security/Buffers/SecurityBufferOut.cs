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

namespace NtApiDotNet.Win32.Security.Buffers
{
    /// <summary>
    /// A security buffer which can only be an output.
    /// </summary>
    public sealed class SecurityBufferOut : SecurityBuffer
    {
        private byte[] _array;
        private int _size;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="type">The type of buffer.</param>
        /// <param name="size">The size of the output buffer.</param>
        public SecurityBufferOut(SecurityBufferType type, int size) : base(type)
        {
            _size = size;
        }

        /// <summary>
        /// Convert to buffer back to an array.
        /// </summary>
        /// <returns>The buffer as an array.</returns>
        public override byte[] ToArray()
        {
            if (_array == null)
                throw new InvalidOperationException("Can't access buffer until it's been populated.");
            return _array;
        }

        internal override SecBuffer ToBuffer()
        {
            return new SecBuffer(Type, _size);
        }

        internal override void FromBuffer(SecBuffer buffer)
        {
            _array = buffer.ToArray();
            _size = _array.Length;
        }
    }
}
