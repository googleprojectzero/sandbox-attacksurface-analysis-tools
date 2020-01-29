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

namespace NtApiDotNet.Ndr
{
#pragma warning disable 1591

    // Marker class for a string type.
    [Serializable]
    public class NdrBaseStringTypeReference : NdrBaseTypeReference
    {
        internal NdrBaseStringTypeReference(NdrFormatCharacter format) : base(format)
        {
        }
    }

    [Serializable]
    public sealed class NdrStringTypeReference : NdrBaseStringTypeReference
    {
        public int StringSize { get; }

        internal NdrStringTypeReference(NdrFormatCharacter format, BinaryReader reader) : base(format)
        {
            reader.ReadByte(); // Padding.
            StringSize = reader.ReadUInt16();
        }

        internal override string FormatType(INdrFormatterInternal context)
        {
            if (StringSize > 0)
            {
                return $"{base.FormatType(context)}[{StringSize}]";
            }
            else
            {
                return base.FormatType(context);
            }
        }

        private int GetCharSize()
        {
            if (Format == NdrFormatCharacter.FC_WSTRING)
                return 2;
            return 1;
        }

        public override int GetSize()
        {
            return StringSize * GetCharSize();
        }
    }

    [Serializable]
    public sealed class NdrConformantStringTypeReference : NdrBaseStringTypeReference
    {
        public NdrCorrelationDescriptor ConformanceDescriptor { get; }

        internal NdrConformantStringTypeReference(NdrParseContext context,
            NdrFormatCharacter format, BinaryReader reader) : base(format)
        {
            NdrFormatCharacter padding = (NdrFormatCharacter)reader.ReadByte();
            if (padding == NdrFormatCharacter.FC_STRING_SIZED)
            {
                ConformanceDescriptor = new NdrCorrelationDescriptor(context, reader);
            }
            else
            {
                ConformanceDescriptor = new NdrCorrelationDescriptor();
            }
        }

        internal override string FormatType(INdrFormatterInternal context)
        {
            string conformance_desc = string.Empty;
            if (ConformanceDescriptor != null && ConformanceDescriptor.IsValid)
            {
                conformance_desc = context.FormatComment(ConformanceDescriptor.ToString());
            }

            if (!ConformanceDescriptor.IsValid)
            {
                return $"{conformance_desc}{base.FormatType(context)}";
            }

            return $"{conformance_desc}{base.FormatType(context)}[{GetCharCount()}]";
        }

        private int GetCharSize()
        {
            if (Format == NdrFormatCharacter.FC_C_WSTRING)
                return 2;
            return 1;
        }

        private int GetCharCount()
        {
            if (ConformanceDescriptor.IsValid
                && ConformanceDescriptor.CorrelationType == NdrCorrelationType.FC_CONSTANT_CONFORMANCE)
            {
                return ConformanceDescriptor.Offset;
            }
            return 1;
        }

        public override int GetSize()
        {
            return GetCharCount() * GetCharSize();
        }

    }

    [Serializable]
    public class NdrStructureStringTypeReference : NdrBaseStringTypeReference
    {
        public int ElementSize { get; }
        public int NumberOfElements { get; }
        internal NdrStructureStringTypeReference(BinaryReader reader) : base(NdrFormatCharacter.FC_SSTRING)
        {
            ElementSize = reader.ReadByte();
            NumberOfElements = reader.ReadUInt16();
        }

        internal override string FormatType(INdrFormatterInternal formatter)
        {
            return $"{base.FormatType(formatter)}<{ElementSize}>[{NumberOfElements}]";
        }
    }

    [Serializable]
    public class NdrConformantStructureStringTypeReference : NdrBaseStringTypeReference
    {
        public int ElementSize { get; }
        public NdrCorrelationDescriptor ConformanceDescriptor { get; }

        internal NdrConformantStructureStringTypeReference(NdrParseContext context, BinaryReader reader) : base(NdrFormatCharacter.FC_C_SSTRING)
        {
            ElementSize = reader.ReadByte();
            if (NdrFormatCharacter.FC_STRING_SIZED == (NdrFormatCharacter)reader.ReadByte())
            {
                // Padding.
                reader.ReadByte();
                ConformanceDescriptor = new NdrCorrelationDescriptor(context, reader);
            }
            else
            {
                ConformanceDescriptor = new NdrCorrelationDescriptor();
            }
        }

        internal override string FormatType(INdrFormatterInternal formatter)
        {
            return $"{base.FormatType(formatter)}<{ElementSize}>[]";
        }
    }

#pragma warning restore 1591
}
