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

namespace NtCoreLib.Utilities.Memory;

/// <summary>
/// Interface to read a cross bitness type to a native type.
/// </summary>
public interface IConvertToNative<T> where T : struct
{
    /// <summary>
    /// Read the cross bitness type from a reader, converting if necessary.
    /// </summary>
    /// <param name="reader">The reader to read from.</param>
    /// <param name="address">The address to read from.</param>
    /// <param name="index">Index of structure to read.</param>
    T Read(IMemoryReader reader, IntPtr address, int index);
}