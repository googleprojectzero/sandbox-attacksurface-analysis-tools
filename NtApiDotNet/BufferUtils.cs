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

using NtApiDotNet.Utilities.Text;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet
{
#pragma warning disable 1591
    public static partial class NtRtl
    {
        [DllImport("ntdll.dll")]
        public static extern void RtlZeroMemory(
            IntPtr Destination,
            IntPtr Length
        );

        [DllImport("ntdll.dll")]
        public static extern void RtlFillMemory(
            IntPtr Destination,
            IntPtr Length,
            byte Fill
        );

        [DllImport("ntdll.dll")]
        public static extern IntPtr RtlCompareMemory(
            IntPtr Source1,
            IntPtr Source2,
            IntPtr Length
        );
    }
#pragma warning restore 1591

    /// <summary>
    /// Some simple utilities to create structure buffers.
    /// </summary>
    public static class BufferUtils
    {
        /// <summary>
        /// Create a buffer based on a passed type.
        /// </summary>
        /// <typeparam name="T">The type to use in the structure buffer.</typeparam>
        /// <param name="value">The value to initialize the buffer with.</param>
        /// <param name="additional_size">Additional byte data after the structure.</param>
        /// <param name="add_struct_size">Indicates if additional_size includes the structure size or not.</param>
        /// <returns>The new structure buffer.</returns>
        public static SafeStructureInOutBuffer<T> CreateBuffer<T>(T value, int additional_size, bool add_struct_size) where T : new()
        {
            return new SafeStructureInOutBuffer<T>(value, additional_size, add_struct_size);
        }

        /// <summary>
        /// Create a buffer based on a passed type.
        /// </summary>
        /// <typeparam name="T">The type to use in the structure buffer.</typeparam>
        /// <param name="value">The value to initialize the buffer with.</param>
        /// <returns>The new structure buffer.</returns>
        public static SafeStructureInOutBuffer<T> CreateBuffer<T>(T value) where T : new()
        {
            return new SafeStructureInOutBuffer<T>(value);
        }

        /// <summary>
        /// Create a buffer based on a passed type.
        /// </summary>
        /// <typeparam name="T">The type to use in the structure buffer.</typeparam>
        /// <param name="value">The value to initialize the buffer with.</param>
        /// <returns>The new structure buffer.</returns>
        public static SafeStructureInOutBuffer<T> ToBuffer<T>(this T value) where T : new()
        {
            return CreateBuffer(value, 0, true);
        }

        /// <summary>
        /// Create a buffer based on a passed type.
        /// </summary>
        /// <typeparam name="T">The type to use in the structure buffer.</typeparam>
        /// <param name="value">The value to initialize the buffer with.</param>
        /// <param name="additional_size">Additional byte data after the structure.</param>
        /// <param name="add_struct_size">Indicates if additional_size includes the structure size or not.</param>
        /// <returns>The new structure buffer.</returns>
        public static SafeStructureInOutBuffer<T> ToBuffer<T>(this T value, int additional_size, bool add_struct_size) where T : new()
        {
            return CreateBuffer(value, additional_size, add_struct_size);
        }

        /// <summary>
        /// Create a buffer based on a byte array.
        /// </summary>
        /// <param name="value">The byte array for the buffer.</param>
        /// <returns>The safe buffer.</returns>
        public static SafeHGlobalBuffer ToBuffer(this byte[] value)
        {
            if (value == null)
            {
                return SafeHGlobalBuffer.Null;
            }
            return new SafeHGlobalBuffer(value);
        }

        /// <summary>
        /// Create an buffer from an array.
        /// </summary>
        /// <typeparam name="T">The array element type, must be a value type.</typeparam>
        /// <param name="value">The array of elements.</param>
        /// <returns>The allocated array buffer.</returns>
        public static SafeHGlobalBuffer ToBuffer<T>(this T[] value) where T : new()
        {
            return new SafeArrayBuffer<T>(value);
        }

        internal static DataStartAttribute GetStructDataAttribute<T>() where T : new()
        {
            return typeof(T).GetCustomAttribute<DataStartAttribute>();
        }

        internal static int GetStructDataOffset<T>() where T : new()
        {
            var attr = GetStructDataAttribute<T>();
            if (attr != null)
            {
                return Marshal.OffsetOf(typeof(T), attr.FieldName).ToInt32();
            }
            return Marshal.SizeOf(typeof(T));
        }

        internal static bool GetIncludeField<T>() where T : new()
        {
            var attr = GetStructDataAttribute<T>();
            if (attr != null)
            {
                return attr.IncludeDataField;
            }
            return true;
        }

        /// <summary>
        /// Read a NUL terminated string for the byte offset.
        /// </summary>
        /// <param name="buffer">The buffer to read from.</param>
        /// <param name="byte_offset">The byte offset to read from.</param>
        /// <returns>The string read from the buffer without the NUL terminator</returns>
        public static string ReadNulTerminatedUnicodeString(SafeBuffer buffer, ulong byte_offset)
        {
            List<char> chars = new List<char>();
            while (byte_offset < buffer.ByteLength)
            {
                char c = buffer.Read<char>(byte_offset);
                if (c == 0)
                {
                    break;
                }
                chars.Add(c);
                byte_offset += 2;
            }
            return new string(chars.ToArray());
        }

        /// <summary>
        /// Read a NUL terminated byte string for the byte offset.
        /// </summary>
        /// <param name="buffer">The buffer to read from.</param>
        /// <param name="byte_offset">The byte offset to read from.</param>
        /// <param name="encoding">Text encoding for the string.</param>
        /// <returns>The string read from the buffer without the NUL terminator</returns>
        public static string ReadNulTerminatedAnsiString(SafeBuffer buffer, ulong byte_offset, Encoding encoding)
        {
            List<byte> chars = new List<byte>();
            while (byte_offset < buffer.ByteLength)
            {
                byte b = buffer.Read<byte>(byte_offset);
                if (b == 0)
                {
                    break;
                }
                chars.Add(b);
                byte_offset++;
            }

            return encoding.GetString(chars.ToArray());
        }

        /// <summary>
        /// Read a NUL terminated ANSI string for the byte offset.
        /// </summary>
        /// <param name="buffer">The buffer to read from.</param>
        /// <param name="byte_offset">The byte offset to read from.</param>
        /// <returns>The string read from the buffer without the NUL terminator</returns>
        public static string ReadNulTerminatedAnsiString(SafeBuffer buffer, ulong byte_offset)
        {
            return ReadNulTerminatedAnsiString(buffer, byte_offset, BinaryEncoding.Instance);
        }

        /// <summary>
        /// Read a char array with length.
        /// </summary>
        /// <param name="buffer">The buffer to read from.</param>
        /// <param name="count">The number of characters to read.</param>
        /// <param name="byte_offset">The byte offset to read from.</param>
        /// <returns>The chars read from the buffer</returns>
        public static char[] ReadCharArray(SafeBuffer buffer, ulong byte_offset, int count)
        {
            char[] ret = new char[count];
            buffer.ReadArray(byte_offset, ret, 0, count);
            return ret;
        }

        /// <summary>
        /// Read a Unicode string string with length.
        /// </summary>
        /// <param name="buffer">The buffer to read from.</param>
        /// <param name="count">The number of characters to read.</param>
        /// <param name="byte_offset">The byte offset to read from.</param>
        /// <returns>The string read from the buffer.</returns>
        public static string ReadUnicodeString(SafeBuffer buffer, ulong byte_offset, int count)
        {
            return new string(ReadCharArray(buffer, byte_offset, count));
        }

        /// <summary>
        /// Write char array.
        /// </summary>
        /// <param name="buffer">The buffer to write to.</param>
        /// <param name="byte_offset">The byte offset to write to.</param>
        /// <param name="value">The chars to write.</param>
        public static void WriteCharArray(SafeBuffer buffer, ulong byte_offset, char[] value)
        {
            buffer.WriteArray(byte_offset, value, 0, value.Length);
        }

        /// <summary>
        /// Write unicode string.
        /// </summary>
        /// <param name="buffer">The buffer to write to.</param>
        /// <param name="byte_offset">The byte offset to write to.</param>
        /// <param name="value">The string value to write.</param>
        public static void WriteUnicodeString(SafeBuffer buffer, ulong byte_offset, string value)
        {
            WriteCharArray(buffer, byte_offset, value.ToCharArray());
        }

        /// <summary>
        /// Read bytes from buffer.
        /// </summary>
        /// <param name="buffer">The buffer to read from.</param>
        /// <param name="byte_offset">The byte offset to read from.</param>
        /// <param name="count">The number of bytes to read.</param>
        /// <returns>The byte array.</returns>
        public static byte[] ReadBytes(SafeBuffer buffer, ulong byte_offset, int count)
        {
            byte[] ret = new byte[count];
            buffer.ReadArray(byte_offset, ret, 0, count);
            return ret;
        }

        /// <summary>
        /// Write bytes to a buffer.
        /// </summary>
        /// <param name="buffer">The buffer to write to.</param>
        /// <param name="byte_offset">The byte offset to write to.</param>
        /// <param name="data">The data to write.</param>
        public static void WriteBytes(SafeBuffer buffer, ulong byte_offset, byte[] data)
        {
            buffer.WriteArray(byte_offset, data, 0, data.Length);
        }

        /// <summary>
        /// Get a structure buffer at a specific offset.
        /// </summary>
        /// <typeparam name="T">The type of structure.</typeparam>
        /// <param name="buffer">The buffer to map.</param>
        /// <param name="offset">The offset into the buffer.</param>
        /// <returns>The structure buffer.</returns>
        /// <remarks>The returned buffer is not owned, therefore you need to maintain the original buffer while operating on this buffer.</remarks>
        public static SafeStructureInOutBuffer<T> GetStructAtOffset<T>(SafeBuffer buffer, int offset) where T : new()
        {
            int length_left = (int)buffer.ByteLength - offset;
            int struct_size = Marshal.SizeOf(typeof(T));
            if (length_left < struct_size)
            {
                throw new ArgumentException("Invalid length for structure");
            }

            return new SafeStructureInOutBuffer<T>(buffer.DangerousGetHandle() + offset, length_left, false);
        }

        /// <summary>
        /// Creates a view of an existing safe buffer.
        /// </summary>
        /// <param name="buffer">The buffer to create a view on.</param>
        /// <param name="offset">The offset from the start of the buffer.</param>
        /// <param name="length">The length of the view.</param>
        /// <returns>The buffer view.</returns>
        /// <remarks>Note that the returned buffer doesn't own the memory, therefore the original buffer
        /// must be maintained for the lifetime of this buffer.</remarks>
        public static SafeBuffer CreateBufferView(SafeBuffer buffer, int offset, int length)
        {
            long total_length = (long)buffer.ByteLength;
            if (offset + length > total_length)
            {
                throw new ArgumentException("Offset and length is larger than the existing buffer");
            }

            return new SafeHGlobalBuffer(buffer.DangerousGetHandle() + offset, length, false);
        }

        /// <summary>
        /// Zero an entire buffer.
        /// </summary>
        /// <param name="buffer">The buffer to zero.</param>
        public static void ZeroBuffer(SafeBuffer buffer)
        {
            NtRtl.RtlZeroMemory(buffer.DangerousGetHandle(), new IntPtr(buffer.GetLength()));
        }

        /// <summary>
        /// Fill an entire buffer with a specific byte value.
        /// </summary>
        /// <param name="buffer">The buffer to full.</param>
        /// <param name="fill">The fill value.</param>
        public static void FillBuffer(SafeBuffer buffer, byte fill)
        {
            NtRtl.RtlFillMemory(buffer.DangerousGetHandle(), new IntPtr(buffer.GetLength()), fill);
        }

        /// <summary>
        /// Compare two buffers for equality.
        /// </summary>
        /// <param name="left">The left buffer.</param>
        /// <param name="left_offset">The offset into the left buffer.</param>
        /// <param name="right">The right buffer.</param>
        /// <param name="right_offset">The offset into the right buffer.</param>
        /// <param name="length">The length to compare.</param>
        /// <returns>True if the buffers are equal.</returns>
        public static bool EqualBuffer(this SafeBuffer left, int left_offset, SafeBuffer right, int right_offset, int length)
        {
            if (length == 0)
            {
                return true;
            }

            long left_length = left.GetLength();
            long right_length = right.GetLength();
            if (left_length < (left_offset + length) 
                || right_length < (right_offset + length))
            {
                return false;
            }

            IntPtr compare_length = new IntPtr(length);
            return NtRtl.RtlCompareMemory(left.DangerousGetHandle() + left_offset, right.DangerousGetHandle() + right_offset, compare_length) == compare_length;
        }

        /// <summary>
        /// Compare a buffer and a byte array for equality.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        /// <param name="offset">The offset into the left buffer.</param>
        /// <param name="compare">The compare byte array.</param>
        /// <returns>True if the buffers are equal.</returns>
        public static bool EqualBuffer(this SafeBuffer buffer, int offset, byte[] compare)
        {
            using (var compare_buffer = compare.ToBuffer())
            {
                return buffer.EqualBuffer(offset, compare_buffer, 0, compare.Length);
            }
        }

        /// <summary>
        /// Find a byte array in a buffer. Returns all instances of the compare array.
        /// </summary>
        /// <param name="buffer">The buffer to find the data in.</param>
        /// <param name="start_offset">Start offset in the buffer.</param>
        /// <param name="compare">The comparison byte array.</param>
        /// <returns>A list of offsets into the buffer where the compare was found.</returns>
        public static IEnumerable<int> FindBuffer(this SafeBuffer buffer, int start_offset, byte[] compare)
        {
            using (var compare_buffer = compare.ToBuffer())
            {
                int max_length = buffer.GetLength() - compare.Length - start_offset;
                for (int i = 0; i < max_length; ++i)
                {
                    if (buffer.EqualBuffer(start_offset + i, compare_buffer, 0, compare.Length))
                    {
                        yield return i + start_offset;
                    }
                }
            }
        }

        /// <summary>
        /// Find a byte array in a buffer. Returns all instances of the compare array.
        /// </summary>
        /// <param name="buffer">The buffer to find the data in.</param>
        /// <param name="compare">The comparison byte array.</param>
        /// <returns>A list of offsets into the buffer where the compare was found.</returns>
        public static IEnumerable<int> FindBuffer(this SafeBuffer buffer, byte[] compare)
        {
            return buffer.FindBuffer(0, compare);
        }
    }
}
