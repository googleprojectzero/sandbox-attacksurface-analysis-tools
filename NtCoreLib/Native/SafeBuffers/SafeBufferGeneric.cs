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

using NtCoreLib.Utilities.Memory;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace NtCoreLib.Native.SafeBuffers;

/// <summary>
/// Safe buffer which acts as a base class for all other SafeBuffer types in the library.
/// </summary>
public abstract class SafeBufferGeneric : SafeBuffer
{
    #region Private Members
    private readonly bool _writable;
    #endregion

    #region Constructors
    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="length">Size of the buffer.</param>
    /// <param name="buffer">An existing pointer to a buffer.</param>
    /// <param name="owns_handle">Specify whether safe handle owns the buffer.</param>
    /// <param name="writable">Inidicates if the underlying buffer is writable.</param>
    protected SafeBufferGeneric(IntPtr buffer, long length, bool owns_handle, bool writable)
      : base(owns_handle)
    {
        LongLength = length;
        Initialize((ulong)length);
        SetHandle(buffer);
        _writable = writable;
    }

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="length">Size of the buffer.</param>
    /// <param name="buffer">An existing pointer to a buffer.</param>
    /// <param name="owns_handle">Specify whether safe handle owns the buffer.</param>
    protected SafeBufferGeneric(IntPtr buffer, long length, bool owns_handle)
        : this(buffer, length, owns_handle, true)
    {
    }

    #endregion

    #region Internal Members
    internal SafeBufferGeneric(bool owns_handle)
        : base(owns_handle)
    {
    }

    internal void InitializeLength(long length)
    {
        Initialize((ulong)length);
        LongLength = length;
    }
    #endregion

    #region Public Properties
    /// <summary>
    /// Length of the allocation.
    /// </summary>
    public int Length => unchecked((int)LongLength);

    /// <summary>
    /// Length of the allocation as a long.
    /// </summary>
    public long LongLength { get; private set; }

    /// <summary>
    /// Get the length as an IntPtr
    /// </summary>
    public IntPtr LengthIntPtr => new(LongLength);

    #endregion

    #region Public Methods
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
        return SafeBufferUtils.ReadNulTerminatedUnicodeString(this, byte_offset);
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
    /// Read a NUL terminated ANSI string for the byte offset.
    /// </summary>
    /// <param name="byte_offset">The byte offset to read from.</param>
    /// <param name="encoding">Text encoding for the string.</param>
    /// <returns>The string read from the buffer without the NUL terminator</returns>
    public string ReadNulTerminatedAnsiString(ulong byte_offset, Encoding encoding)
    {
        return SafeBufferUtils.ReadNulTerminatedAnsiString(this, byte_offset, encoding);
    }

    /// <summary>
    /// Read a NUL terminated ANSI string
    /// </summary>
    /// <param name="encoding">Text encoding for the string.</param>
    /// <returns>The string read from the buffer without the NUL terminator</returns>
    public string ReadNulTerminatedAnsiString(Encoding encoding)
    {
        return ReadNulTerminatedAnsiString(0, encoding);
    }

    /// <summary>
    /// Read a NUL terminated ANSI string for the byte offset.
    /// </summary>
    /// <param name="byte_offset">The byte offset to read from.</param>
    /// <returns>The string read from the buffer without the NUL terminator</returns>
    public string ReadNulTerminatedAnsiString(ulong byte_offset)
    {
        return SafeBufferUtils.ReadNulTerminatedAnsiString(this, byte_offset);
    }

    /// <summary>
    /// Read a NUL terminated ANSI string
    /// </summary>
    /// <returns>The string read from the buffer without the NUL terminator</returns>
    public string ReadNulTerminatedAnsiString()
    {
        return ReadNulTerminatedAnsiString(0);
    }

    /// <summary>
    /// Read a unicode string from the buffer.
    /// </summary>
    /// <param name="byte_offset">The offset into the buffer to read.</param>
    /// <param name="count">The number of characters to read.</param>
    /// <returns>The read unicode string.</returns>
    public string ReadUnicodeString(ulong byte_offset, int count)
    {
        return SafeBufferUtils.ReadUnicodeString(this, byte_offset, count);
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
    /// Read an ANSI string string with length.
    /// </summary>
    /// <param name="count">The number of characters to read.</param>
    /// <param name="byte_offset">The byte offset to read from.</param>
    /// <returns>The string read from the buffer.</returns>
    public string ReadAnsiString(ulong byte_offset, int count)
    {
        return SafeBufferUtils.ReadAnsiString(this, byte_offset, count);
    }

    /// <summary>
    /// Read an ANSI string string with length.
    /// </summary>
    /// <param name="count">The number of characters to read.</param>
    /// <returns>The string read from the buffer.</returns>
    public string ReadAnsiString(int count)
    {
        return ReadAnsiString(0, count);
    }

    /// <summary>
    /// Write a unicode string to the buffer.
    /// </summary>
    /// <param name="byte_offset">The offset into the buffer to write.</param>
    /// <param name="value">The value to write.</param>
    public void WriteUnicodeString(ulong byte_offset, string value)
    {
        SafeBufferUtils.WriteUnicodeString(this, byte_offset, value);
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
        return SafeBufferUtils.ReadBytes(this, byte_offset, count);
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
        SafeBufferUtils.WriteBytes(this, byte_offset, data);
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
    /// Read array from the buffer.
    /// </summary>
    /// <typeparam name="T">The type to read.</typeparam>
    /// <param name="offset">The offset into the buffer.</param>
    /// <param name="count">The number of elements to read.</param>
    /// <returns>The read array.</returns>
    public T[] ReadArray<T>(int offset, int count) where T : struct
    {
        T[] ret = new T[count];
        ReadArray((ulong)offset, ret, 0, count);
        return ret;
    }

    /// <summary>
    /// Zero an entire buffer.
    /// </summary>
    public void ZeroBuffer()
    {
        SafeBufferUtils.ZeroBuffer(this);
    }

    /// <summary>
    /// Fill an entire buffer with a specific byte value.
    /// </summary>
    /// <param name="fill">The fill value.</param>
    public void FillBuffer(byte fill)
    {
        SafeBufferUtils.FillBuffer(this, fill);
    }

    /// <summary>
    /// Get a structured buffer object at a specified offset.
    /// </summary>
    /// <typeparam name="T">The type of structure.</typeparam>
    /// <param name="offset">The offset into the buffer.</param>
    /// <returns>The structured buffer object.</returns>
    public SafeStructureInOutBuffer<T> GetStructAtOffset<T>(int offset) where T : new()
    {
        return SafeBufferUtils.GetStructAtOffset<T>(this, offset);
    }

    /// <summary>
    /// Get the buffer as a memory stream
    /// </summary>
    /// <returns></returns>
    public Stream GetStream()
    {
        return new UnmanagedMemoryStream(this, 0, LongLength, _writable ? FileAccess.ReadWrite : FileAccess.Read);
    }

    /// <summary>
    /// Create a view accessor over the full buffer.
    /// </summary>
    /// <returns>The view accessor.</returns>
    public UnmanagedMemoryAccessor CreateViewAccessor()
    {
        return CreateViewAccessor(0, LongLength);
    }

    /// <summary>
    /// Create a view accessor.
    /// </summary>
    /// <param name="offset">Offset into the buffer</param>
    /// <param name="capacity">Size of view.</param>
    /// <returns>The view accessor.</returns>
    public UnmanagedMemoryAccessor CreateViewAccessor(long offset, long capacity)
    {
        return CreateViewAccessor(offset, capacity, _writable);
    }

    /// <summary>
    /// Create a view accessor.
    /// </summary>
    /// <param name="offset">Offset into the buffer</param>
    /// <param name="capacity">Size of view.</param>
    /// <param name="writable">True to make the view writable. False for read-only</param>
    /// <returns>The view accessor.</returns>
    public UnmanagedMemoryAccessor CreateViewAccessor(long offset, long capacity, bool writable)
    {
        return new UnmanagedMemoryAccessor(new SafeBufferView(this, writable), offset, capacity,
            writable ? FileAccess.ReadWrite : FileAccess.Read);
    }
    #endregion

    #region Unsafe Methods
    /// <summary>
    /// Reads a structure from the buffer.
    /// </summary>
    /// <typeparam name="T">The type of the structure to read.</typeparam>
    /// <returns>The read structure.</returns>
    /// <remarks>This is unsafe and does no length checks. Use with caution.</remarks>
    public T ReadStructUnsafe<T>()
    {
        return Marshal.PtrToStructure<T>(DangerousGetHandle());
    }

    /// <summary>
    /// Reads a structure from the buffer.
    /// </summary>
    /// <typeparam name="T">The type of the structure to read.</typeparam>
    /// <returns>The read structure.</returns>
    /// <remarks>This is unsafe and does no length checks. Use with caution.</remarks>
    public T ReadStructUnsafe<T>(int offset)
    {
        return Marshal.PtrToStructure<T>(DangerousGetHandle() + offset);
    }

    /// <summary>
    /// Reads an array from the buffer.
    /// </summary>
    /// <typeparam name="T">The type of the structure to read.</typeparam>
    /// <returns>The read array.</returns>
    /// <remarks>This is unsafe and does no length checks. Use with caution.</remarks>
    public T[] ReadArrayUnsafe<T>(int offset, int count)
    {
        IntPtr ptr = DangerousGetHandle() + offset;
        return ptr.ReadArray<T>(count);
    }

    /// <summary>
    /// Writes a structure to the buffer.
    /// </summary>
    /// <typeparam name="T">The type of the structure to write.</typeparam>
    /// <param name="value">The structure to write.</param>
    /// <remarks>This is unsafe and does no length checks. Use with caution.</remarks>
    public void WriteStructureUnsafe<T>(T value)
    {
        Marshal.StructureToPtr(value, DangerousGetHandle(), false);
    }

    /// <summary>
    /// Read a NUL terminated unicode string from the buffer.
    /// </summary>
    /// <returns>The unicode string.</returns>
    /// <remarks>This is unsafe and does no length checks. Use with caution.</remarks>
    public string ReadNulTerminatedUnicodeStringUnsafe()
    {
        return Marshal.PtrToStringUni(DangerousGetHandle());
    }

    #endregion
}
