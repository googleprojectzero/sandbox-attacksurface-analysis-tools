//  Copyright 2020 Google Inc. All Rights Reserved.
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
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;

namespace NtApiDotNet
{
    /// <summary>
    /// Class which is allocated from the process heap.
    /// </summary>
    public class SafeProcessHeapBuffer : SafeBufferGeneric
    {
        internal SafeProcessHeapBuffer() 
            : base(IntPtr.Zero, 0, true)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="length">Size of the buffer to allocate.</param>
        public SafeProcessHeapBuffer(int length)
          : this(length, length)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="data">Initialization data for the buffer.</param>
        public SafeProcessHeapBuffer(byte[] data)
            : this(data.Length)
        {
            WriteArray(0, data, 0, data.Length);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="allocation_length">The length of data to allocate.</param>
        /// <param name="total_length">The total length to reflect in the Length property.</param>
        protected SafeProcessHeapBuffer(int allocation_length, int total_length)
            : this(new IntPtr(NtHeap.Current.Allocate(HeapAllocFlags.None, allocation_length)), total_length, true)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="length">Size of the buffer.</param>
        /// <param name="buffer">An existing pointer to an existing HGLOBAL allocated buffer.</param>
        /// <param name="owns_handle">Specify whether safe handle owns the buffer.</param>
        public SafeProcessHeapBuffer(IntPtr buffer, int length, bool owns_handle)
          : base(buffer, length, owns_handle)
        {
        }

        /// <summary>
        /// Get a buffer which represents NULL.
        /// </summary>
        public static SafeProcessHeapBuffer Null { get { return new SafeProcessHeapBuffer(IntPtr.Zero, 0, false); } }

        /// <summary>
        /// Overridden ReleaseHandle method.
        /// </summary>
        /// <returns>True if successfully released the memory.</returns>
        protected override bool ReleaseHandle()
        {
            if (!IsInvalid)
            {
                return NtHeap.Current.Free(HeapAllocFlags.None, handle.ToInt64(), false).IsSuccess();
            }
            return true;
        }

        /// <summary>
        /// Detaches the current buffer and allocates a new one.
        /// </summary>
        /// <returns>The detached buffer.</returns>
        /// <remarks>The original buffer will become invalid after this call.</remarks>
        [ReliabilityContract(Consistency.MayCorruptInstance, Cer.MayFail)]
        public SafeProcessHeapBuffer Detach()
        {
            return Detach(Length);
        }

        /// <summary>
        /// Detaches the current buffer and allocates a new one.
        /// </summary>
        /// <param name="length">Specify a new length for the detached buffer. Must be &lt;= Length.</param>
        /// <returns>The detached buffer.</returns>
        /// <remarks>The original buffer will become invalid after this call.</remarks>
        [ReliabilityContract(Consistency.MayCorruptInstance, Cer.MayFail)]
        public SafeProcessHeapBuffer Detach(int length)
        {
            if (length > Length)
            {
                throw new ArgumentException("Buffer length is smaller than new length");
            }

            RuntimeHelpers.PrepareConstrainedRegions();
            try // Needed for constrained region.
            {
                IntPtr handle = DangerousGetHandle();
                SetHandleAsInvalid();
                return new SafeProcessHeapBuffer(handle, length, true);
            }
            finally
            {
            }
        }
    }
}
