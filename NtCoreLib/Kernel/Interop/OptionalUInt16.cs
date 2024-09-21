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

using System.Runtime.InteropServices;

namespace NtCoreLib.Kernel.Interop;

/// <summary>
/// This class allows a function to specify an optional uint16.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public class OptionalUInt16
{
    /// <summary>
    /// Optional value
    /// </summary>
    public ushort Value;

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="value">The value</param>
    public OptionalUInt16(ushort value)
    {
        Value = value;
    }

    /// <summary>
    /// Constructor
    /// </summary>
    public OptionalUInt16() : this(0)
    {
    }

    /// <summary>
    /// Implicit conversion
    /// </summary>
    /// <param name="value">The value</param>
    public static implicit operator OptionalUInt16(ushort value)
    {
        return new OptionalUInt16(value);
    }
}
