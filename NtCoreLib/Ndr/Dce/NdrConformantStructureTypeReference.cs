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
public sealed class NdrConformantStructureTypeReference : NdrBaseStructureTypeReference
{
    public NdrBaseTypeReference ConformantArray { get; }

    public NdrPointerInfoTypeReference PointerInfo { get; }

    public override bool Conformant => true;

    internal NdrConformantStructureTypeReference(NdrFormatCharacter format, NdrParseContext context, BinaryReader reader)
        : base(context, format, reader)
    {
        ConformantArray = Read(context, ReadTypeOffset(reader));
        if (format == NdrFormatCharacter.FC_CPSTRUCT)
        {
            // Read out FC_PP type.
            reader.ReadByte();
            PointerInfo = new NdrPointerInfoTypeReference(context, reader);
        }
        ReadMemberInfo(context, reader);
    }

    protected override List<NdrStructureMember> PopulateMembers()
    {
        if (_base_members.LastOrDefault() is not NdrBaseStructureTypeReference last_member || !last_member.Conformant)
        {
            _base_members.Add(ConformantArray);
        }

        var members = base.PopulateMembers();
        PointerInfo?.FixupMembers(members);
        return members;
    }
}

#pragma warning restore 1591

