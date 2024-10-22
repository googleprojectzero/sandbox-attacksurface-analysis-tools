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

using System;
using System.IO;

namespace NtCoreLib.Ndr.Marshal;

/// <summary>
/// Structure to represent a window handle such as a HWND or HMENU.
/// </summary>
public struct NdrWindowHandle : INdrStructure
{
    private int _handle;
    private const int MAGIC = 0x48746457; // WtdH

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="hwnd">The HWND as a pointer.</param>
    public NdrWindowHandle(IntPtr hwnd) : this(hwnd.ToInt32())
    {
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="hwnd">The HWND as an integer.</param>
    public NdrWindowHandle(int hwnd)
    {
        _handle = hwnd;
    }

    int INdrStructure.GetAlignment()
    {
        return 4;
    }

    void INdrStructure.Marshal(INdrMarshalBuffer marshal)
    {
        marshal.WriteInt32(MAGIC);
        marshal.WriteInt32(_handle);
    }

    void INdrStructure.Unmarshal(INdrUnmarshalBuffer unmarshal)
    {
        if (unmarshal.ReadInt32() != MAGIC)
        {
            throw new InvalidDataException("Invalid marshaled HWND.");
        }
        _handle = unmarshal.ReadInt32();
    }
}