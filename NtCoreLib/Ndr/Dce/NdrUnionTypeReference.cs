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
using System.IO;
using System.Linq;

namespace NtCoreLib.Ndr.Dce;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
[Serializable]
public sealed class NdrUnionTypeReference : NdrComplexTypeReference
{
    public NdrFormatCharacter SwitchType { get; }
    public int SwitchIncrement { get; }
    public NdrUnionArms Arms { get; }
    public NdrCorrelationDescriptor Correlation { get; }
    public string SelectorName { get; set; }
    public bool NonEncapsulated => Format == NdrFormatCharacter.FC_NON_ENCAPSULATED_UNION;

    internal NdrUnionTypeReference(NdrFormatCharacter format, NdrParseContext context, BinaryReader reader)
        : base($"Union_{context.TypeCache.GetNextComplexId()}", format)
    {
        int switch_type = reader.ReadByte();
        if (NonEncapsulated)
        {
            SwitchType = (NdrFormatCharacter)switch_type;
            Correlation = new NdrCorrelationDescriptor(context, reader);
            int arms_ofs = ReadTypeOffset(reader);
            if (!context.UnionArmsCache.ContainsKey(arms_ofs))
            {
                context.UnionArmsCache[arms_ofs] = new NdrUnionArms(context, arms_ofs);
            }
            Arms = context.UnionArmsCache[arms_ofs];
        }
        else
        {
            SwitchIncrement = switch_type >> 4 & 0xF;
            SwitchType = (NdrFormatCharacter)(switch_type & 0xF);
            Correlation = new NdrCorrelationDescriptor();
            Arms = new NdrUnionArms(context, reader);
        }
    }

    public override int MemberCount => Arms.Arms.Count();

    private protected override string FormatType(INdrFormatterContext context)
    {
        return $"union {Name}";
    }

    public override int GetSize()
    {
        return Arms.MemorySize + SwitchIncrement;
    }
}

#pragma warning restore 1591

