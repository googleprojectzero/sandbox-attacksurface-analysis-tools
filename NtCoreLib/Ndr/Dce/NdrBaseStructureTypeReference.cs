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

// NOTE: This file is a modified version of NdrParser.cs from OleViewDotNet
// https://github.com/tyranid/oleviewdotnet. It's been relicensed from GPLv3 by
// the original author James Forshaw to be used under the Apache License for this
// project.

using NtCoreLib.Ndr.Formatter;
using NtCoreLib.Ndr.Parser;
using System;
using System.Collections.Generic;
using System.IO;

namespace NtCoreLib.Ndr.Dce;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
[Serializable]
public class NdrBaseStructureTypeReference : NdrComplexTypeReference
{
    protected List<NdrBaseTypeReference> _base_members;
    private List<NdrStructureMember> _members;

    public int Alignment { get; }
    public int MemorySize { get; }
    public virtual bool Conformant => false;

    protected virtual List<NdrStructureMember> PopulateMembers()
    {
        List<NdrStructureMember> members = new();
        int current_offset = 0;
        foreach (var type in _base_members)
        {
            if (type is NdrStructureAlignTypeReference align)
            {
                current_offset = align.Align(current_offset);
            }
            else
            {
                if (type is not NdrStructurePaddingTypeReference)
                {
                    members.Add(new NdrStructureMember(type, current_offset, $"Member{current_offset:X}"));
                }
                current_offset += type.GetSize();
            }
        }
        return members;
    }

    private List<NdrStructureMember> GetMembers()
    {
        _members ??= PopulateMembers();
        return _members;
    }

    public IEnumerable<NdrBaseTypeReference> MembersTypes => _base_members.AsReadOnly();

    public IEnumerable<NdrStructureMember> Members => GetMembers().AsReadOnly();

    public override int MemberCount => GetMembers().Count;

    internal NdrBaseStructureTypeReference(NdrParseContext context, NdrFormatCharacter format, BinaryReader reader)
        : base($"Struct_{context.TypeCache.GetNextComplexId()}", format)
    {
        Alignment = reader.ReadByte();
        MemorySize = reader.ReadUInt16();
        _base_members = new List<NdrBaseTypeReference>();
    }

    internal void ReadMemberInfo(NdrParseContext context, BinaryReader reader)
    {
        NdrBaseTypeReference curr_type;
        while ((curr_type = Read(context, reader)) != null)
        {
            _base_members.Add(curr_type);
        }
    }

    private protected override string FormatType(INdrFormatterContext context)
    {
        return $"struct {Name}";
    }

    public override int GetSize()
    {
        return MemorySize;
    }

    protected override void OnFixupLateBoundTypes()
    {
        foreach (var member in _base_members)
        {
            member.FixupLateBoundTypes();
        }
    }
}

#pragma warning restore 1591
