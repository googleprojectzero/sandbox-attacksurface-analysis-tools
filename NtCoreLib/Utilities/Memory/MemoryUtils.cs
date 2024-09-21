//  Copyright 2023 Google Inc. All Rights Reserved.
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

namespace NtCoreLib.Utilities.Memory;

/// <summary>
/// Utilities for memory access.
/// </summary>
public static class MemoryUtils
{
    /// <summary>
    /// Create a memory reader for a process.
    /// </summary>
    /// <param name="process">The process to create the reader for.</param>
    /// <returns>The memory reader.</returns>
    /// <exception cref="ArgumentException">Throw if invalid process.</exception>
    public static IMemoryReader CreateMemoryReader(NtProcess process)
    {
        if (!Environment.Is64BitProcess && process.Is64Bit)
        {
            throw new ArgumentException("Class does not support 32 to 64 bit reading.");
        }

        if (Environment.Is64BitProcess != process.Is64Bit)
        {
            return new CrossBitnessMemoryReader(process);
        }

        return new ProcessMemoryReader(process);
    }

    /// <summary>
    /// Create a 32-bit memory reader from an existing reader.
    /// </summary>
    /// <param name="reader">The reader to create the 32bit reader for.</param>
    /// <returns>The memory reader.</returns>
    /// <remarks>If the reader is already a 32-bit reader then returns the original value.</remarks>
    public static IMemoryReader Create32BitMemoryReader(IMemoryReader reader)
    {
        if (!Environment.Is64BitProcess || reader is CrossBitnessMemoryReader)
            return reader;
        return new CrossBitnessMemoryReader(reader);
    }

    /// <summary>
    /// Create a memory reader for the current process.
    /// </summary>
    /// <returns>The memory reader.</returns>
    public static IMemoryReader CreateMemoryReader()
    {
        return new CurrentProcessMemoryReader();
    }
}
