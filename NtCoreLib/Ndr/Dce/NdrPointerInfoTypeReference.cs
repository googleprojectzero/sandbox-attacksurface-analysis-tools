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

using NtCoreLib.Ndr.Parser;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NtCoreLib.Ndr.Dce;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
[Serializable]
public sealed class NdrPointerInfoTypeReference : NdrBaseTypeReference
{
    public NdrFormatCharacter BasePointerType { get; }
    public NdrFormatCharacter SubPointerType { get; }
    public int Iterations { get; private set; }
    public int Increment { get; private set; }
    public int OffsetToArray { get; private set; }
    public IEnumerable<NdrPointerInfoInstance> PointerInstances { get; }

    private IEnumerable<NdrPointerInfoInstance> ReadComplex(NdrParseContext context, BinaryReader reader, bool has_interations)
    {
        if (has_interations)
        {
            Iterations = reader.ReadInt16();
        }

        Increment = reader.ReadInt16();
        OffsetToArray = reader.ReadInt16();
        int num_of_pointers = reader.ReadInt16();
        while (num_of_pointers > 0)
        {
            yield return new NdrPointerInfoInstance(context, reader);
            num_of_pointers--;
        }
    }

    internal NdrPointerInfoTypeReference(NdrParseContext context, BinaryReader reader)
        : base(NdrFormatCharacter.FC_PP)
    {
        List<NdrPointerInfoInstance> instances = new();
        reader.ReadByte(); // Padding.
        BasePointerType = (NdrFormatCharacter)reader.ReadByte();
        SubPointerType = (NdrFormatCharacter)reader.ReadByte();

        switch (BasePointerType)
        {
            case NdrFormatCharacter.FC_NO_REPEAT:
                instances.Add(new NdrPointerInfoInstance(context, reader));
                break;
            case NdrFormatCharacter.FC_FIXED_REPEAT:
                instances.AddRange(ReadComplex(context, reader, true));
                break;
            case NdrFormatCharacter.FC_VARIABLE_REPEAT:
                instances.AddRange(ReadComplex(context, reader, false));
                break;
        }

        while ((NdrFormatCharacter)reader.ReadByte() != NdrFormatCharacter.FC_END)
        {
        }

        PointerInstances = instances;
    }

    internal void FixupMembers(List<NdrStructureMember> members)
    {
        var pointer_types = PointerInstances.ToDictionary(p => p.OffsetInMemory);

        foreach (var member in members)
        {
            if (pointer_types.ContainsKey(member.Offset))
            {
                member.MemberType = pointer_types[member.Offset].PointerType;
            }
        }
    }
}

#pragma warning restore 1591

