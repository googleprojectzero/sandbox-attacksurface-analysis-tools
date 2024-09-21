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
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
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

        private static int GetArraySize(int count, bool align)
        {
            int array_size = _element_size * count;
            if (align)
            {
                // Align the array buffer to 8 byte alignment. Assumes that allocations
                // are always at least allocated on 8 byte boundaries.
                return (array_size + 7) & ~7;
            }
            return array_size;
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
            : base(GetArraySize(array.Length, additional_size > 0) + additional_size)
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

                int size = GetArraySize(Count, true);
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
}
