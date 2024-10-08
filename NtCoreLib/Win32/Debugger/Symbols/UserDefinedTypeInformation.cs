﻿//  Copyright 2020 Google Inc. All Rights Reserved.
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

using System.Collections.Generic;
using System.Linq;
using NtCoreLib.Win32.Debugger.Interop;

namespace NtCoreLib.Win32.Debugger.Symbols;

/// <summary>
/// Symbol information for an enumerated type.
/// </summary>
public class UserDefinedTypeInformation : TypeInformation
{
    /// <summary>
    /// The members of the UDT.
    /// </summary>
    public IReadOnlyList<UserDefinedTypeMember> Members { get; }

    /// <summary>
    /// Indicates the UDT is a union.
    /// </summary>
    public bool Union { get; }

    /// <summary>
    /// Get the list of members based on their offset in the structure..
    /// </summary>
    public IReadOnlyList<IReadOnlyList<UserDefinedTypeMember>> UniqueMembers { get; }

    internal UserDefinedTypeInformation(long size, int type_index, SymbolLoadedModule module,
        string name, bool union, IReadOnlyList<UserDefinedTypeMember> members)
        : base(SymTagEnum.SymTagUDT, size, type_index, module, name)
    {
        Members = members;
        Union = union;
        var groups = members.GroupBy(m => m.Offset).OrderBy(g => g.Key);
        var lists = groups.Select(g => (IReadOnlyList<UserDefinedTypeMember>)g.AsEnumerable().ToList());
        UniqueMembers = lists.ToList().AsReadOnly();
    }
}
