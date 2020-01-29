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
using System.Text;

namespace NtApiDotNet.Ndr
{
#pragma warning disable 1591
    [Serializable]
    public sealed class NdrUnionArm
    {
        public NdrBaseTypeReference ArmType { get; }
        public int CaseValue { get; }

        internal NdrUnionArm(NdrParseContext context, BinaryReader reader)
        {
            CaseValue = reader.ReadInt32();
            ArmType = ReadArmType(context, reader);
        }

        internal static NdrBaseTypeReference ReadArmType(NdrParseContext context, BinaryReader reader)
        {
            ushort type = reader.ReadUInt16();
            if ((type & 0x8F00) == 0x8000)
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

    [Serializable]
    public sealed class NdrUnionArms
    {
        public int MemorySize { get; }
        public IEnumerable<NdrUnionArm> Arms { get; }
        public NdrBaseTypeReference DefaultArm { get; }
        public int Alignment { get; }

        internal NdrUnionArms(NdrParseContext context, BinaryReader reader)
        {
            MemorySize = reader.ReadUInt16();
            ushort start_word = reader.ReadUInt16();
            Alignment = (start_word >> 12) & 0xF;
            int count = start_word & 0xFFF;

            List<NdrUnionArm> arms = new List<NdrUnionArm>();
            while (count > 0)
            {
                arms.Add(new NdrUnionArm(context, reader));
                count--;
            }
            Arms = arms.AsReadOnly();
            DefaultArm = NdrUnionArm.ReadArmType(context, reader);
        }

        internal NdrUnionArms(NdrParseContext context, int ofs)
            : this(context, NdrBaseTypeReference.GetReader(context, ofs))
        {
        }
    }

    [Serializable]
    public sealed class NdrUnionTypeReference : NdrComplexTypeReference
    {
        public NdrFormatCharacter SwitchType { get; }
        public int SwitchIncrement { get; }
        public NdrUnionArms Arms { get; }
        public NdrCorrelationDescriptor Correlation { get; }
        public bool NonEncapsulated => Format == NdrFormatCharacter.FC_NON_ENCAPSULATED_UNION;

        internal NdrUnionTypeReference(NdrFormatCharacter format, NdrParseContext context, BinaryReader reader)
            : base($"Union_{context.TypeCache.GetNextComplexId()}", format)
        {
            int switch_type = reader.ReadByte();
            if (NonEncapsulated)
            {
                SwitchType = (NdrFormatCharacter)switch_type;
                Correlation = new NdrCorrelationDescriptor(context, reader);
                Arms = new NdrUnionArms(context, ReadTypeOffset(reader));
            }
            else
            {
                SwitchIncrement = (switch_type >> 4) & 0xF;
                SwitchType = (NdrFormatCharacter)(switch_type & 0xF);
                Correlation = new NdrCorrelationDescriptor();
                Arms = new NdrUnionArms(context, reader);
            }
        }

        internal override string FormatType(INdrFormatterInternal context)
        {
            return $"{(Format == NdrFormatCharacter.FC_NON_ENCAPSULATED_UNION ? "union" : "struct")} {Name}";
        }

        internal override string FormatComplexType(INdrFormatterInternal context)
        {
            int indent = 4;
            StringBuilder builder = new StringBuilder();
            builder.Append(context.FormatComment("Memory Size: {0}", GetSize())).AppendLine();
            builder.Append(FormatType(context)).AppendLine(" {");

            if (!NonEncapsulated)
            {
                builder.Append(' ', indent).AppendFormat("{0} Selector;", new NdrSimpleTypeReference(SwitchType).FormatType(context)).AppendLine();
                builder.Append(' ', indent).AppendLine("union { ");
                indent *= 2;
            }
            else
            {
                builder.Append(context.FormatComment(Correlation.ToString())).AppendLine();
            }

            int index = 0;
            foreach (NdrUnionArm arm in Arms.Arms)
            {
                builder.Append(' ', indent).AppendFormat("/* case: {0} */", arm.CaseValue).AppendLine();
                builder.Append(' ', indent).AppendFormat("{0} Member_{1};", arm.ArmType.FormatType(context), index++).AppendLine();
            }

            if (Arms.DefaultArm != null)
            {
                builder.Append(' ', indent).AppendLine("/* default */");
                if (Arms.DefaultArm.Format != NdrFormatCharacter.FC_ZERO)
                {
                    builder.Append(' ', indent).AppendFormat("{0} Default;", new NdrSimpleTypeReference(Arms.DefaultArm.Format).FormatType(context)).AppendLine();
                }
            }

            if (!NonEncapsulated)
            {
                indent /= 2;
                builder.Append(' ', indent).AppendLine("};");
            }

            builder.AppendLine("};");
            return builder.ToString();
        }

        public override int GetSize()
        {
            return Arms.MemorySize + SwitchIncrement;
        }
    }

#pragma warning restore 1591
}
