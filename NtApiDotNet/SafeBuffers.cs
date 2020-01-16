//  Copyright 2019 Google Inc. All Rights Reserved.
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
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet
{
    /// <summary>
    /// Safe buffer to hold a security object which be deleted by RtlDeleteSecurityObject.
    /// </summary>
    public sealed class SafeSecurityObjectBuffer : SafeBuffer
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        public SafeSecurityObjectBuffer() : base(true)
        {
            Initialize(0);
        }

        /// <summary>
        /// Overridden ReleaseHandle method.
        /// </summary>
        /// <returns>True if successfully released the memory.</returns>
        protected override bool ReleaseHandle()
        {
            return NtRtl.RtlDeleteSecurityObject(ref handle).IsSuccess();
        }
    }

    /// <summary>
    /// Non-generic buffer to hold an IO_STATUS_BLOCK.
    /// </summary>
    public sealed class SafeIoStatusBuffer : SafeStructureInOutBuffer<IoStatus>
    {
    }

    /// <summary>
    /// Safe buffer to contain a list of structures.
    /// </summary>
    internal class SafeArrayBuffer<T> : SafeHGlobalBuffer where T : new()
    {
        /// <summary>
        /// The count of elements of the array.
        /// </summary>
        public int Count { get; }

        private static readonly int _element_size = Marshal.SizeOf(typeof(T));

        private static int GetArraySize(T[] array)
        {
            return _element_size * array.Length;
        }

        private SafeArrayBuffer() : base(IntPtr.Zero, 0, false)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="array">Array of elements.</param>
        /// <param name="additional_size">Additional data to place after the array.</param>
        public SafeArrayBuffer(T[] array, int additional_size)
            : base(GetArraySize(array) + additional_size)
        {
            Count = array.Length;
            IntPtr ptr = DangerousGetHandle();
            for (int i = 0; i < array.Length; ++i)
            {
                Marshal.StructureToPtr(array[i], ptr + (i * _element_size), false);
            }
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="array">Array of elements.</param>
        public SafeArrayBuffer(T[] array)
            : this(array, 0)
        {
        }

        /// <summary>
        /// Get a reference to the additional data.
        /// </summary>
        public SafeHGlobalBuffer Data
        {
            get
            {
                if (IsClosed || IsInvalid)
                    throw new ObjectDisposedException("handle");

                int size = Count * _element_size;
                int length = Length - size;
                return new SafeHGlobalBuffer(handle + size, length < 0 ? 0 : length, false);
            }
        }

        /// <summary>
        /// Get a NULL safe array buffer.
        /// </summary>
        new static public SafeArrayBuffer<T> Null => new SafeArrayBuffer<T>();

        /// <summary>
        /// Dispose buffer.
        /// </summary>
        /// <param name="disposing">True if disposing.</param>
        protected override void Dispose(bool disposing)
        {
            IntPtr ptr = DangerousGetHandle();
            for (int i = 0; i < Count; ++i)
            {
                Marshal.DestroyStructure(ptr + (i * _element_size), typeof(T));
            }
            base.Dispose(disposing);
        }
    }

    internal sealed class SafeHandleListHandle : SafeHGlobalBuffer
    {
        private DisposableList<SafeKernelObjectHandle> _handles;
        public SafeHandleListHandle(IEnumerable<SafeKernelObjectHandle> handles)
          : base(IntPtr.Size * handles.Count())
        {
            _handles = handles.ToDisposableList();
            IntPtr buffer = handle;
            for (int i = 0; i < _handles.Count; ++i)
            {
                Marshal.WriteIntPtr(buffer, _handles[i].DangerousGetHandle());
                buffer += IntPtr.Size;
            }
        }

        protected override bool ReleaseHandle()
        {
            _handles.Dispose();
            return base.ReleaseHandle();
        }
    }

    internal sealed class SafeStringBuffer : SafeHGlobalBuffer
    {
        public SafeStringBuffer(string str) : base(Encoding.Unicode.GetBytes(str + "\0"))
        {
        }
    }
}
