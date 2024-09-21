﻿//  Copyright 2016 Google Inc. All Rights Reserved.
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
/// Optional value.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public class OptionalTokenDefaultDacl
{
    /// <summary>
    /// Optional value.
    /// </summary>
    public TokenDefaultDacl Value;

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="value">The value</param>
    public OptionalTokenDefaultDacl(TokenDefaultDacl value)
    {
        Value = value;
    }

    /// <summary>
    /// Constructor
    /// </summary>
    public OptionalTokenDefaultDacl() : this(default)
    {
    }

    /// <summary>
    /// Implicit conversion
    /// </summary>
    /// <param name="value">The value.</param>
    public static implicit operator OptionalTokenDefaultDacl(TokenDefaultDacl value)
    {
        return new OptionalTokenDefaultDacl(value);
    }
}
