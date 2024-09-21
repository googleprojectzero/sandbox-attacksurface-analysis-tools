//  Copyright 2021 Google Inc. All Rights Reserved.
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

using NtCoreLib.Utilities.Collections;
using NtCoreLib.Win32.Security.Interop;
using System;
using System.Linq;

namespace NtCoreLib.Win32.Security.Buffers;

/// <summary>
/// A security buffer which can be an input and output.
/// </summary>
/// <remarks>If you create with the ReadOnly or ReadOnlyWithCheck types then the 
/// array will not be updated.</remarks>
public sealed class SecurityBufferInOut : SecurityBuffer, ISecurityBufferInOut
{
    private ArraySegment<byte> _array;

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="type">The type of buffer.</param>
    /// <param name="data">The data for the input.</param>
    public SecurityBufferInOut(SecurityBufferType type, byte[] data) : base(type)
    {
        _array = new ArraySegment<byte>(data);
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="type">The type of buffer.</param>
    /// <param name="data">The data for the input.</param>
    /// <param name="offset">The offset into the array.</param>
    /// <param name="count">Number of bytes in the input.</param>
    public SecurityBufferInOut(SecurityBufferType type, byte[] data, int offset, int count) : base(type)
    {
        _array = new ArraySegment<byte>(data, offset, count);
    }

    /// <summary>
    /// Convert to buffer back to an array.
    /// </summary>
    /// <returns>The buffer as an array.</returns>
    public override byte[] ToArray()
    {
        return _array.ToArray();
    }

    internal override SecBuffer ToBuffer(DisposableList list)
    {
        return SecBuffer.Create(_type, ToArray(), list);
    }

    internal override void FromBuffer(SecBuffer buffer)
    {
        if (_type.HasFlagSet(SecurityBufferType.ReadOnly | SecurityBufferType.ReadOnlyWithChecksum))
        {
            return;
        }
        _array = new ArraySegment<byte>(buffer.ToArray());
        _type = buffer.BufferType;
    }

    int ISecurityBufferOut.Size => _array.Count;

    void ISecurityBufferOut.Update(SecurityBufferType type, byte[] data)
    {
        if (_type.HasFlagSet(SecurityBufferType.ReadOnly | SecurityBufferType.ReadOnlyWithChecksum))
        {
            return;
        }
        _array = new ArraySegment<byte>(data);
        _type = type;
    }
}
