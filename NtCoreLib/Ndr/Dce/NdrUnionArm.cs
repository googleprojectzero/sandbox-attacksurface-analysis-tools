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
using System.IO;
using NtCoreLib.Ndr.Parser;

namespace NtCoreLib.Ndr.Dce;
#pragma warning disable 1591
[Serializable]
public sealed class NdrUnionArm
{
    public NdrBaseTypeReference ArmType { get; }
    public int CaseValue { get; }
    public string Name { get; set; }

    private static string FormatCaseLabel(int case_value)
    {
        if (case_value < 0)
        {
            return $"minus_{Math.Abs(case_value)}";
        }
        return case_value.ToString();
    }


    internal NdrUnionArm(NdrParseContext context, BinaryReader reader)
    {
        CaseValue = reader.ReadInt32();
        ArmType = ReadArmType(context, reader);
        Name = $"Arm_{FormatCaseLabel(CaseValue)}";
    }

    internal static NdrBaseTypeReference ReadArmType(NdrParseContext context, BinaryReader reader)
    {
        ushort type = reader.ReadUInt16();
        if ((type & 0xFF00) == 0x8000)
        {
            return new NdrSimpleTypeReference((NdrFormatCharacter)(type & 0xFF));
        }
        else if (type == 0)
        {
            return new NdrSimpleTypeReference(NdrFormatCharacter.FC_ZERO);
        }
        else if (type == 0xFFFF)
        {
            return null;
        }
        else
        {
            reader.BaseStream.Position = reader.BaseStream.Position - 2;
            return NdrBaseTypeReference.Read(context, NdrBaseTypeReference.ReadTypeOffset(reader));
        }
    }
}

#pragma warning restore 1591

