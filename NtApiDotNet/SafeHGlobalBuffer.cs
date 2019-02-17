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
            RuntimeHelpers.PrepareConstrainedRegions();
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
}
