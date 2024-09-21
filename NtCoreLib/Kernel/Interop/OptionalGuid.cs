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
/// This class allows a function to specify an optional Guid
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public class OptionalGuid
{
    /// <summary>
    /// Optional Guid
    /// </summary>
    public Guid Value;

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="guid">The GUID to initialize</param>
    public OptionalGuid(Guid guid)
    {
        Value = guid;
    }

    /// <summary>
    /// Constructor
    /// </summary>
    public OptionalGuid() : this(Guid.Empty)
    {
    }

    /// <summary>
    /// Implicit conversion
    /// </summary>
    /// <param name="guid">The value</param>
    public static implicit operator OptionalGuid(Guid guid)
    {
        return new OptionalGuid(guid);
    }
}
