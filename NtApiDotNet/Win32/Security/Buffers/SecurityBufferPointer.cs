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
    /// A security buffer which takes a raw pointer. The lifetime of the pointer
    /// should be managed manually by the caller.
    /// </summary>
    public sealed class SecurityBufferPointer : SecurityBuffer
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="type">The type of buffer.</param>
        /// <param name="pointer">The raw pointer.</param>
        /// <param name="size">The size of the raw pointer.</param>
        public SecurityBufferPointer(SecurityBufferType type, IntPtr pointer, int size) : base(type)
        {
            Pointer = pointer;
            Size = size;
        }

        /// <summary>
        /// The size of the buffer.
        /// </summary>
        public int Size { get; private set; }

        /// <summary>
        /// The pointer for the buffer. The lifetime needs to be manually managed.
        /// </summary>
        public IntPtr Pointer { get; private set; }

        /// <summary>
        /// This will free pointer using the SSPI APIs. Used to release automatically allocated
        /// buffers. If you control the value of the Pointer you don't need to release it.
        /// </summary>
        public void Release()
        {
            SecurityNativeMethods.FreeContextBuffer(Pointer);
            Pointer = IntPtr.Zero;
        }

        /// <summary>
        /// Convert to buffer back to an array.
        /// </summary>
        /// <returns>The buffer as an array.</returns>
        public override byte[] ToArray()
        {
            if (Pointer == IntPtr.Zero)
                return null;
            byte[] ret = new byte[Size];
            Marshal.Copy(Pointer, ret, 0, Size);
            return ret;
        }

        internal override void FromBuffer(SecBuffer buffer)
        {
            if (_type.HasFlagSet(SecurityBufferType.ReadOnly | SecurityBufferType.ReadOnlyWithChecksum))
            {
                return;
            }
            _type = buffer.BufferType;
        }

        internal override SecBuffer ToBuffer(DisposableList list)
        {
            return new SecBuffer(Type, Pointer, Size);
        }
    }
}
