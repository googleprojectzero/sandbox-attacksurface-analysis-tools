//  Copyright 2016 Google Inc. All Rights Reserved.
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

namespace NtCoreLib.Kernel.Interop;

/// <summary>
/// This class allows a function to specify an optional pointer.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public class OptionalPointer
{
    /// <summary>
    /// Optional length
    /// </summary>
    public IntPtr Value;

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="value">The value</param>
    public OptionalPointer(IntPtr value)
    {
        Value = value;
    }

    /// <summary>
    /// Constructor
    /// </summary>
    public OptionalPointer() : this(IntPtr.Zero)
    {
    }

    /// <summary>
    /// Implicit conversion
    /// </summary>
    /// <param name="value">The value</param>
    public static implicit operator OptionalPointer(IntPtr value)
    {
        return new OptionalPointer(value);
    }
}
