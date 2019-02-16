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
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace NtApiDotNet
{
    /// <summary>
    /// A safe handle to an allocated global buffer.
    /// </summary>
    public class SafeHGlobalBuffer : SafeBuffer
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="length">Size of the buffer to allocate.</param>
        public SafeHGlobalBuffer(int length)
          : this(length, length)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="allocation_length">The length of data to allocate.</param>
        /// <param name="total_length">The total length to reflect in the Length property.</param>
        protected SafeHGlobalBuffer(int allocation_length, int total_length)
            : this(Marshal.AllocHGlobal(allocation_length), total_length, true)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="length">Size of the buffer.</param>
        /// <param name="buffer">An existing pointer to an existing HGLOBAL allocated buffer.</param>
        /// <param name="owns_handle">Specify whether safe handle owns the buffer.</param>
        public SafeHGlobalBuffer(IntPtr buffer, int length, bool owns_handle)
          : base(owns_handle)
        {
            Length = length;
            Initialize((ulong)length);
            SetHandle(buffer);
        }

        /// <summary>
        /// Get a buffer which represents NULL.
        /// </summary>
        public static SafeHGlobalBuffer Null { get { return new SafeHGlobalBuffer(IntPtr.Zero, 0, false); } }

        /// <summary>
        /// Resize the SafeBuffer.
        /// </summary>
        /// <param name="new_length"></param>
        [ReliabilityContract(Consistency.MayCorruptInstance, Cer.None)]
        public virtual void Resize(int new_length)
        {
            IntPtr free_handle = IntPtr.Zero;
            try
            {
                byte[] old_data = new byte[Length];
                Marshal.Copy(handle, old_data, 0, Length);
                free_handle = Marshal.AllocHGlobal(new_length);
                Marshal.Copy(old_data, 0, free_handle, Math.Min(new_length, Length));
                free_handle = Interlocked.Exchange(ref handle, free_handle);
                Length = new_length;
                Initialize((ulong)new_length);
            }
            finally
            {
                if (free_handle != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(free_handle);
                }
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="data">Initialization data for the buffer.</param>
        public SafeHGlobalBuffer(byte[] data) : this(data.Length)
        {
            Marshal.Copy(data, 0, handle, data.Length);
        }

        /// <summary>
        /// Length of the allocation.
        /// </summary>
        public int Length
        {
            get; private set;
        }

        /// <summary>
        /// Get the length as an IntPtr
        /// </summary>
        public IntPtr LengthIntPtr
        {
            get { return new IntPtr(Length); }
        }

        /// <summary>
        /// Overridden ReleaseHandle method.
        /// </summary>
        /// <returns>True if successfully released the memory.</returns>
        protected override bool ReleaseHandle()
        {
            if (!IsInvalid)
            {
                Marshal.FreeHGlobal(handle);
                handle = IntPtr.Zero;
            }
            return true;
        }

        /// <summary>
        /// Convert the safe handle to an array of bytes.
        /// </summary>
        /// <returns>The data contained in the allocaiton.</returns>
        public byte[] ToArray()
        {
            return ReadBytes(Length);
        }

        /// <summary>
        /// Read a NUL terminated string for the byte offset.
        /// </summary>
        /// <param name="byte_offset">The byte offset to read from.</param>
        /// <returns>The string read from the buffer without the NUL terminator</returns>
        public string ReadNulTerminatedUnicodeString(ulong byte_offset)
        {
            return BufferUtils.ReadNulTerminatedUnicodeString(this, byte_offset);
        }

        /// <summary>
        /// Read a NUL terminated string
        /// </summary>
        /// <returns>The string read from the buffer without the NUL terminator</returns>
        public string ReadNulTerminatedUnicodeString()
        {
            return ReadNulTerminatedUnicodeString(0);
        }

        /// <summary>
        /// Read a unicode string from the buffer.
        /// </summary>
        /// <param name="byte_offset">The offset into the buffer to read.</param>
        /// <param name="count">The number of characters to read.</param>
        /// <returns>The read unicode string.</returns>
        public string ReadUnicodeString(ulong byte_offset, int count)
        {
            return BufferUtils.ReadUnicodeString(this, byte_offset, count);
        }

        /// <summary>
        /// Read a unicode string from the buffer.
        /// </summary>
        /// <param name="count">The number of characters to read.</param>
        /// <returns>The read unicode string.</returns>
        public string ReadUnicodeString(int count)
        {
            return ReadUnicodeString(0, count);
        }

        /// <summary>
        /// Write a unicode string to the buffer.
        /// </summary>
        /// <param name="byte_offset">The offset into the buffer to write.</param>
        /// <param name="value">The value to write.</param>
        public void WriteUnicodeString(ulong byte_offset, string value)
        {
            BufferUtils.WriteUnicodeString(this, byte_offset, value);
        }

        /// <summary>
        /// Write a unicode string to the buffer.
        /// </summary>
        /// <param name="value">The value to write.</param>
        public void WriteUnicodeString(string value)
        {
            WriteUnicodeString(0, value);
        }

        /// <summary>
        /// Read an array of bytes from the buffer.
        /// </summary>
        /// <param name="byte_offset">The offset into the buffer.</param>
        /// <param name="count">The number of bytes to read.</param>
        /// <returns>The read bytes.</returns>
        public byte[] ReadBytes(ulong byte_offset, int count)
        {
            return BufferUtils.ReadBytes(this, byte_offset, count);
        }

        /// <summary>
        /// Read an array of bytes from the buffer.
        /// </summary>
        /// <param name="count">The number of bytes to read.</param>
        /// <returns>The read bytes.</returns>
        public byte[] ReadBytes(int count)
        {
            return ReadBytes(0, count);
        }

        /// <summary>
        /// Write an array of bytes to the buffer.
        /// </summary>
        /// <param name="byte_offset">The offset into the buffer.</param>
        /// <param name="data">The bytes to write.</param>
        public void WriteBytes(ulong byte_offset, byte[] data)
        {
            BufferUtils.WriteBytes(this, byte_offset, data);
        }

        /// <summary>
        /// Write an array of bytes to the buffer.
        /// </summary>
        /// <param name="data">The bytes to write.</param>
        public void WriteBytes(byte[] data)
        {
            WriteBytes(0, data);
        }

        /// <summary>
        /// Zero an entire buffer.
        /// </summary>
        public void ZeroBuffer()
        {
            BufferUtils.ZeroBuffer(this);
        }

        /// <summary>
        /// Fill an entire buffer with a specific byte value.
        /// </summary>
        /// <param name="fill">The fill value.</param>
        public void FillBuffer(byte fill)
        {
            BufferUtils.FillBuffer(this, fill);
        }

        /// <summary>
        /// Get a structured buffer object at a specified offset.
        /// </summary>
        /// <typeparam name="T">The type of structure.</typeparam>
        /// <param name="offset">The offset into the buffer.</param>
        /// <returns>The structured buffer object.</returns>
        public SafeStructureInOutBuffer<T> GetStructAtOffset<T>(int offset) where T : new()
        {
            return BufferUtils.GetStructAtOffset<T>(this, offset);
        }

        /// <summary>
        /// Detaches the current buffer and allocates a new one.
        /// </summary>
        /// <returns>The detached buffer.</returns>
        /// <remarks>The original buffer will become invalid after this call.</remarks>
        [ReliabilityContract(Consistency.MayCorruptInstance, Cer.MayFail)]
        public SafeHGlobalBuffer Detach()
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
        public SafeHGlobalBuffer Detach(int length)
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
                return new SafeHGlobalBuffer(handle, length, true);
            }
            finally
            {
            }
        }
    }

    /// <summary>
    /// Safe handle for an in/out structure buffer.
    /// </summary>
    /// <typeparam name="T">The type of structure as the base of the memory allocation.</typeparam>
    public class SafeStructureInOutBuffer<T> : SafeHGlobalBuffer where T : new()
    {
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

        // Private constructor for Null buffer.
        private SafeStructureInOutBuffer(int dummy_length) : base(IntPtr.Zero, dummy_length, false)
        {
        }

        /// <summary>
        /// Get a buffer which represents NULL.
        /// </summary>
        new public static SafeStructureInOutBuffer<T> Null { get { return new SafeStructureInOutBuffer<T>(0); } }

        /// <summary>
        /// Constructor, initializes buffer with a default structure.
        /// </summary>
        /// <param name="additional_size">Additional data to add to structure buffer.</param>
        /// <param name="add_struct_size">If true additional_size is added to structure size, otherwise reflects the total size.</param>
        public SafeStructureInOutBuffer(int additional_size, bool add_struct_size)
            : this(new T(), additional_size, add_struct_size)
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

        /// <summary>
        /// Convert the buffer back to a structure.
        /// </summary>
        public virtual T Result
        {
            get
            {
                if (IsClosed || IsInvalid)
                    throw new ObjectDisposedException("handle");

                return (T)Marshal.PtrToStructure(handle, typeof(T));
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
    }

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
        public int Count { get; private set; }

        private static int _element_size = Marshal.SizeOf(typeof(T));

        private static int GetArraySize(T[] array)
        {
            return _element_size * array.Length;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="array">Array of elements.</param>
        public SafeArrayBuffer(T[] array)
            : base(GetArraySize(array))
        {
            Count = array.Length;
            IntPtr ptr = DangerousGetHandle();
            for (int i = 0; i < array.Length; ++i)
            {
                Marshal.StructureToPtr(array[i], ptr + (i * _element_size), false);
            }
        }

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
