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

namespace NtApiDotNet.Ndr
{
#pragma warning disable 1591
    [Serializable]
    public sealed class NdrUnknownTypeReference : NdrBaseTypeReference
    {
        static HashSet<NdrFormatCharacter> _formats = new HashSet<NdrFormatCharacter>();
        internal NdrUnknownTypeReference(NdrFormatCharacter format) : base(format)
        {
            if (_formats.Add(format))
            {
                System.Diagnostics.Debug.WriteLine(format.ToString());
            }
        }

        internal override string FormatType(INdrFormatterInternal formatter)
        {
            return $"{formatter.FormatComment("Unhandled")} {base.FormatType(formatter)}";
        }
    }

    [Serializable]
    public sealed class NdrRangeTypeReference : NdrBaseTypeReference
    {
        public NdrBaseTypeReference RangeType { get; }
        public int MinValue { get; }
        public int MaxValue { get; }

        public NdrRangeTypeReference(BinaryReader reader) : base(NdrFormatCharacter.FC_RANGE)
        {
            RangeType = new NdrSimpleTypeReference((NdrFormatCharacter)reader.ReadByte());
            MinValue = reader.ReadInt32();
            MaxValue = reader.ReadInt32();
        }

        internal override string FormatType(INdrFormatterInternal context)
        {
            return $"{context.FormatComment("range: {0},{1}", MinValue, MaxValue)} {RangeType.FormatType(context)}";
        }

        public override int GetSize()
        {
            return RangeType.GetSize();
        }
    }

    [Serializable]
    public sealed class NdrIndirectTypeReference : NdrBaseTypeReference
    {
        public NdrBaseTypeReference RefType { get; private set; }

        internal void FixupType(NdrBaseTypeReference ref_type)
        {
            RefType = ref_type;
        }

        internal NdrIndirectTypeReference() : base(NdrFormatCharacter.FC_ZERO)
        {
        }

        internal override string FormatType(INdrFormatterInternal context)
        {
            return RefType.FormatType(context);
        }

        public override int GetSize()
        {
            return RefType.GetSize();
        }

        public override string ToString()
        {
            return RefType.ToString();
        }
    }

    [Serializable]
    public sealed class NdrPipeTypeReference : NdrBaseTypeReference
    {
        // IDL is typedef pipe TYPE CHAR_PIPE_TYPE;

        public NdrBaseTypeReference BaseType { get; }
        public byte Alignment { get; }

        internal NdrPipeTypeReference(NdrParseContext context, BinaryReader reader)
            : base(NdrFormatCharacter.FC_PIPE)
        {
            Alignment = reader.ReadByte();
            BaseType = Read(context, ReadTypeOffset(reader));
        }

        internal override string FormatType(INdrFormatterInternal context)
        {
            return $"{context.FormatComment("FC_PIPE")} {BaseType.FormatType(context)}";
        }

        public override int GetSize()
        {
            return BaseType.GetSize();
        }
    }

    [Serializable]
    public class NdrSupplementTypeReference : NdrBaseTypeReference
    {
        public NdrFormatCharacter BaseType { get; }
        public NdrBaseTypeReference SupplementType { get; }

        // Supplementary arguments depend on the type. For bind context this is flags + context id,
        // for strings it's lower and upper range bounds.
        public int Argument1 { get; }
        public int Argument2 { get; }

        internal NdrSupplementTypeReference(NdrParseContext context, BinaryReader reader)
            : base(NdrFormatCharacter.FC_SUPPLEMENT)
        {
            BaseType = ReadFormat(reader);
            SupplementType = Read(context, ReadTypeOffset(reader));
            Argument1 = reader.ReadInt32();
            Argument2 = reader.ReadInt32();
        }

        internal override string FormatType(INdrFormatterInternal context)
        {
            string comment = $"FC_SUPPLEMENT {BaseType}";
            if (SupplementType is NdrBaseStringTypeReference)
            {
                comment = $"{comment} Range({Argument1}, {Argument2})";
            }
            else if (SupplementType is NdrHandleTypeReference)
            {
                comment = $"{comment} Flags: {Argument1:X} ContextID: {Argument2:X})";
            }

            return $"{context.FormatComment(comment)} {SupplementType.FormatType(context)}";
        }

        public override int GetSize()
        {
            return IntPtr.Size;
        }
    }
#pragma warning restore 1591
}
