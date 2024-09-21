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
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Buffers
{
    /// <summary>
    /// Class to represent a security buffer we expect to be allocated by the SSPI.
    /// </summary>
    internal class SecurityBufferAllocMem : SecurityBuffer
    {
        private byte[] _array;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="type">The type of the buffer.</param>
        public SecurityBufferAllocMem(SecurityBufferType type) : base(type)
        {
        }

        /// <summary>
        /// Convert to buffer back to an array.
        /// </summary>
        /// <returns>The buffer as an array.</returns>
        public override byte[] ToArray()
        {
            if (_array == null)
                throw new InvalidOperationException("Can't access buffer until it's been allocated.");
            return _array;
        }

        internal override void FromBuffer(SecBuffer buffer)
        {
            if (buffer.pvBuffer == IntPtr.Zero)
            {
                _array = new byte[0];
                return;
            }
            _array = new byte[buffer.cbBuffer];
            Marshal.Copy(buffer.pvBuffer, _array, 0, _array.Length);
            SecurityNativeMethods.FreeContextBuffer(buffer.pvBuffer);
            buffer.pvBuffer = IntPtr.Zero;
            _type = buffer.BufferType;
        }

        internal override SecBuffer ToBuffer(DisposableList list)
        {
            return new SecBuffer(_type);
        }
    }
}
