//  Copyright 2020 Google Inc. All Rights Reserved.
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

namespace NtCoreLib.Win32.Debugger.Symbols;

/// <summary>
/// Represents a member of a UDT.
/// </summary>
public class UserDefinedTypeMember
{
    /// <summary>
    /// The type of the member.
    /// </summary>
    public TypeInformation Type { get; }
    /// <summary>
    /// The name of the member.
    /// </summary>
    public string Name { get; }
    /// <summary>
    /// The offset into the UDT.
    /// </summary>
    public int Offset { get; }
    /// <summary>
    /// The size of the member.
    /// </summary>
    public long Size => Type.Size;

    internal UserDefinedTypeMember(TypeInformation type, string name, int offset)
    {
        Type = type;
        Name = name;
        Offset = offset;
    }
}
