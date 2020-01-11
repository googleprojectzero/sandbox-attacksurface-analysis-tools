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
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Safe handle for an in/out structure buffer.
    /// </summary>
    /// <typeparam name="T">The type of structure as the base of the memory allocation.</typeparam>
    public class SafeStructureInOutBuffer<T> : SafeHGlobalBuffer where T : new()
    {
        #region Constructors
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">Structure value to initialize the buffer.</param>
        public SafeStructureInOutBuffer(T value)
            : this(value, 0, true)
        {
        }

        /// <summary>
        /// Constructor, initializes buffer with a default structure.
        /// </summary>
        public SafeStructureInOutBuffer()
            : this(new T(), 0, true)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="length">Size of the buffer.</param>
        /// <param name="buffer">An existing pointer to an existing HGLOBAL allocated buffer.</param>
        /// <param name="owns_handle">Specify whether safe handle owns the buffer.</param>
        public SafeStructureInOutBuffer(IntPtr buffer, int length, bool owns_handle)
            : base(buffer, length, owns_handle)
        {
        }

        /// <summary>
        /// Constructor, initializes buffer with a default structure.
        /// </summary>
        /// <param name="additional_size">Additional data to add to structure buffer.</param>
        /// <param name="add_struct_size">If true additional_size is added to structure size, otherwise reflects the total size.</param>
        public SafeStructureInOutBuffer(int additional_size, bool add_struct_size)
            : this(new T(), additional_size, add_struct_size)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">Structure value to initialize the buffer.</param>
        /// <param name="additional_size">Additional data to add to structure buffer.</param>
        /// <param name="add_struct_size">If true additional_size is added to structure size, otherwise reflects the total size.</param>
        public SafeStructureInOutBuffer(T value, int additional_size, bool add_struct_size)
            : this(value, GetTotalLength(additional_size, add_struct_size))
        {
        }

        #endregion

        #region Static Properties
        /// <summary>
        /// Get a buffer which represents NULL.
        /// </summary>
        new public static SafeStructureInOutBuffer<T> Null { get { return new SafeStructureInOutBuffer<T>(0); } }
        #endregion

        #region Protected Members
        /// <summary>
        /// Overridden ReleaseHandle method.
        /// </summary>
        /// <returns>True if successfully released the memory.</returns>
        protected override bool ReleaseHandle()
        {
            if (!IsInvalid)
            {
                Marshal.DestroyStructure(handle, typeof(T));
            }
            return base.ReleaseHandle();
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Get or set the result structure in the memory buffer.
        /// </summary>
        public virtual T Result
        {
            get
            {
                if (IsClosed || IsInvalid)
                    throw new ObjectDisposedException("handle");

                return (T)Marshal.PtrToStructure(handle, typeof(T));
            }

            set
            {
                if (IsClosed || IsInvalid)
                    throw new ObjectDisposedException("handle");

                Marshal.StructureToPtr(value, handle, true);
            }
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

                int size = BufferUtils.GetStructDataOffset<T>();
                int length = Length - size;
                return new SafeHGlobalBuffer(handle + size, length < 0 ? 0 : length, false);
            }
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Detaches the current buffer and allocates a new one.
        /// </summary>
        /// <returns>The detached buffer.</returns>
        /// <remarks>The original buffer will become invalid after this call.</remarks>
        [ReliabilityContract(Consistency.MayCorruptInstance, Cer.MayFail)]
        new public SafeStructureInOutBuffer<T> Detach()
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
        new public SafeStructureInOutBuffer<T> Detach(int length)
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
                return new SafeStructureInOutBuffer<T>(handle, length, true);
            }
            finally
            {
            }
        }
        #endregion

        #region Private Members

        // Private constructor for Null buffer.
        private SafeStructureInOutBuffer(int dummy_length) : base(IntPtr.Zero, dummy_length, false)
        {
        }

        private static int GetTotalLength(int additional_size, bool add_struct_size)
        {
            if (add_struct_size)
            {
                int data_offset = BufferUtils.GetIncludeField<T>()
                    ? Marshal.SizeOf(typeof(T)) : BufferUtils.GetStructDataOffset<T>();
                return data_offset + additional_size;
            }
            return additional_size;
        }

        private static int GetAllocationLength(int length)
        {
            // Always ensure we at least allocate the entire structure length.
            return Math.Max(Marshal.SizeOf(typeof(T)), length);
        }

        private SafeStructureInOutBuffer(T value, int total_length)
            : base(GetAllocationLength(total_length), total_length)
        {
            Marshal.StructureToPtr(value, handle, false);
        }

        #endregion
    }
}
