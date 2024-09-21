//  Copyright 2018 Google Inc. All Rights Reserved.
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
using System.IO;

namespace NtCoreLib.Utilities.Memory;

/// <summary>
/// Interface to read memory from a source based on an address. This can support reader from 32-bit structures
/// from 64-bit processes and handling the conversion.
/// </summary>
public interface IMemoryReader
{
    /// <summary>
    /// Read a byte.
    /// </summary>
    /// <param name="address">The address to read.</param>
    /// <returns>The read value.</returns>
    byte ReadByte(IntPtr address);
    /// <summary>
    /// Read an array of bytes.
    /// </summary>
    /// <param name="address">The address to read.</param>
    /// <param name="length">The length to read.</param>
    /// <returns>The read value.</returns>
    byte[] ReadBytes(IntPtr address, int length);
    /// <summary>
    /// Read an int16.
    /// </summary>
    /// <param name="address">The address to read.</param>
    /// <returns>The read value.</returns>
    short ReadInt16(IntPtr address);
    /// <summary>
    /// Read an pointer.
    /// </summary>
    /// <param name="address">The address to read.</param>
    /// <returns>The read value.</returns>
    IntPtr ReadIntPtr(IntPtr address);
    /// <summary>
    /// Read an int32.
    /// </summary>
    /// <param name="address">The address to read.</param>
    /// <returns>The read value.</returns>
    int ReadInt32(IntPtr address);
    /// <summary>
    /// Read a structure.
    /// </summary>
    /// <typeparam name="T">The native type to read.</typeparam>
    /// <param name="address">The address to read.</param>
    /// <param name="index">Index to read, used to offset to a value in an array.</param>
    /// <returns>The read value.</returns>
    T ReadStruct<T>(IntPtr address, int index = 0) where T : struct;
    /// <summary>
    /// Read an array of structures.
    /// </summary>
    /// <typeparam name="T">The native type to read.</typeparam>
    /// <param name="address">The address to read.</param>
    /// <param name="count">The number of structures to read..</param>
    /// <returns>The read value.</returns>
    T[] ReadArray<T>(IntPtr address, int count) where T : struct;
    /// <summary>
    /// Read a NUL terminated ANSI string.
    /// </summary>
    /// <param name="address">The address to read.</param>
    /// <returns>The read value.</returns>
    string ReadAnsiStringZ(IntPtr address);
    /// <summary>
    /// Read a NUL terminated Unicode string.
    /// </summary>
    /// <param name="address">The address to read.</param>
    /// <returns>The read value.</returns>
    string ReadUnicodeStringZ(IntPtr address);
    /// <summary>
    /// Get a stream at a specified address,
    /// </summary>
    /// <param name="address">The address to start from.</param>
    /// <param name="length">The maximum length of the stream.</param>
    /// <returns>The reader.</returns>
    Stream GetStream(IntPtr address, int length = int.MaxValue);
    /// <summary>
    /// Is true if the reader is in-process and you can also use the addresses separately.
    /// </summary>
    bool InProcess { get; }
    /// <summary>
    /// Size of a pointer value.
    /// </summary>
    int PointerSize { get; }
    /// <summary>
    /// If the target of the reader is 64 bit.
    /// </summary>
    bool Is64Bit { get; }
}
