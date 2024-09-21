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

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using NtCoreLib.Ndr.Parser;

namespace NtCoreLib.Ndr.Dce;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
[Serializable]
public sealed class NdrBogusStructureTypeReference : NdrBaseStructureTypeReference
{
    public NdrBaseTypeReference ConformantArray { get; }

    public override bool Conformant => ConformantArray != null;

    internal NdrBogusStructureTypeReference(NdrParseContext context, NdrFormatCharacter format, BinaryReader reader)
        : base(context, format, reader)
    {
        ConformantArray = Read(context, ReadTypeOffset(reader));
        int pointer_ofs = ReadTypeOffset(reader);
        ReadMemberInfo(context, reader);
        if (pointer_ofs >= 0)
        {
            BinaryReader pointer_reader = GetReader(context, pointer_ofs);
            for (int i = 0; i < _base_members.Count; ++i)
            {
                if (_base_members[i].Format == NdrFormatCharacter.FC_POINTER)
                {
                    _base_members[i] = Read(context, pointer_reader);
                }
            }
        }
    }

    protected override List<NdrStructureMember> PopulateMembers()
    {
        if (ConformantArray != null)
        {
            var last_member = _base_members.LastOrDefault() as NdrBaseStructureTypeReference;
            if (last_member == null || !last_member.Conformant)
            {
                _base_members.Add(ConformantArray);
            }
        }

        return base.PopulateMembers();
    }
}

#pragma warning restore 1591

