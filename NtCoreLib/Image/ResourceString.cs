//  Copyright 2023 Google LLC. All Rights Reserved.
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

using NtCoreLib.Native.SafeHandles;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NtCoreLib.Image;

/// <summary>
/// Class to represent a resource string which can be a string or an ID.
/// </summary>
public sealed class ResourceString
{
    /// <summary>
    /// The resource string as a string.
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// The resource string as an ID.
    /// </summary>
    public int? Id { get; }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="value">The resource string as an string.</param>
    public ResourceString(string value)
    {
        Value = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="id">The resource string as an ID.</param>
    public ResourceString(int id)
    {
        Value = $"#{id}";
        Id = id;
    }

    /// <summary>
    /// Overridden ToString method.
    /// </summary>
    /// <returns>The resource string as a string.</returns>
    public override string ToString()
    {
        return Value;
    }

    internal static ResourceString Create(IntPtr ptr)
    {
        if (ptr.ToInt64() < 0x10000)
        {
            return new ResourceString(ptr.ToInt32());
        }
        return new ResourceString(Marshal.PtrToStringUni(ptr));
    }

    internal SafeResourceStringHandle ToHandle()
    {
        if (Id.HasValue)
        {
            return new SafeResourceStringHandle(Id.Value);
        }
        return new SafeResourceStringHandle(Value);
    }

    /// <summary>
    /// Equality.
    /// </summary>
    /// <param name="obj">The object to compare to.</param>
    /// <returns>True if equal.</returns>
    public override bool Equals(object obj)
    {
        return obj is ResourceString res_str &&
               Value.Equals(res_str.Value, StringComparison.OrdinalIgnoreCase) &&
               Id == res_str.Id;
    }

    /// <summary>
    /// Get hash code.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        int hashCode = -1015948038;
        hashCode = hashCode * -1521134295 + EqualityComparer<string>.Default.GetHashCode(Value);
        hashCode = hashCode * -1521134295 + Id.GetHashCode();
        return hashCode;
    }
}
