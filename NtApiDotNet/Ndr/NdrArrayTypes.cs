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
using System.Text;

namespace NtApiDotNet.Ndr
{
#pragma warning disable 1591
    [Serializable]
    public abstract class NdrBaseArrayTypeReference : NdrBaseTypeReference
    {
        public int Alignment { get; }
        public NdrBaseTypeReference ElementType { get; private set; }
        public NdrPointerInfoTypeReference PointerLayout { get; private set; }
        public int ElementCount => GetElementCount();
        public int ElementSize => GetElementSize();

        internal NdrBaseArrayTypeReference(NdrParseContext context, NdrFormatCharacter format, BinaryReader reader) : base(format)
        {
            Alignment = reader.ReadByte();
        }

        internal void ReadElementType(NdrParseContext context, BinaryReader reader)
        {
            NdrBaseTypeReference type = Read(context, reader);
            if (type is NdrPointerInfoTypeReference pointer_layout)
            {
                PointerLayout = pointer_layout;
                ElementType = Read(context, reader);
            }
            else
            {
                ElementType = type;
            }
        }

        protected abstract int GetElementCount();

        protected virtual int GetElementSize()
        {
            return ElementType.GetSize();
        }

        public override int GetSize()
        {
            return ElementCount * ElementSize;
        }

        internal override string FormatType(INdrFormatterInternal context)
        {
            return $"{ElementType.FormatType(context)}[{(ElementCount == 0 ? string.Empty : ElementCount.ToString())}]";
        }

        protected override void OnFixupLateBoundTypes()
        {
            ElementType = GetIndirectType(ElementType);
        }
    }

    [Serializable]
    public sealed class NdrSimpleArrayTypeReference : NdrBaseArrayTypeReference
    {
        public int TotalSize { get; }

        internal NdrSimpleArrayTypeReference(NdrParseContext context, NdrFormatCharacter format, BinaryReader reader) : base(context, format, reader)
        {
            if (format == NdrFormatCharacter.FC_SMFARRAY)
            {
                TotalSize = reader.ReadUInt16();
            }
            else
            {
                TotalSize = reader.ReadInt32();
            }

            ReadElementType(context, reader);
        }

        protected override int GetElementCount()
        {
            return ElementSize > 0 ? TotalSize / ElementSize : 0;
        }

        public override int GetSize()
        {
            return TotalSize;
        }
    }

    [Serializable]
    public sealed class NdrConformantArrayTypeReference : NdrBaseArrayTypeReference
    {
        private readonly int _element_size;

        public NdrCorrelationDescriptor ConformanceDescriptor { get; }
        public NdrCorrelationDescriptor VarianceDescriptor { get; }

        internal NdrConformantArrayTypeReference(NdrFormatCharacter format, NdrParseContext context,
            BinaryReader reader) : base(context, format, reader)
        {
            _element_size = reader.ReadInt16();
            ConformanceDescriptor = new NdrCorrelationDescriptor(context, reader);
            if (format == NdrFormatCharacter.FC_CVARRAY)
            {
                VarianceDescriptor = new NdrCorrelationDescriptor(context, reader);
            }
            else
            {
                VarianceDescriptor = new NdrCorrelationDescriptor();
            }
            ReadElementType(context, reader);
        }

        protected override int GetElementSize()
        {
            return _element_size;
        }

        protected override int GetElementCount()
        {
            if (VarianceDescriptor.IsValid && VarianceDescriptor.IsConstant)
            {
                return VarianceDescriptor.Offset;
            }

            if (ConformanceDescriptor.IsValid && ConformanceDescriptor.IsConstant)
            {
                return ConformanceDescriptor.Offset;
            }

            return 0;
        }

        internal override string FormatType(INdrFormatterInternal context)
        {
            StringBuilder builder = new StringBuilder();
            if (ConformanceDescriptor.IsValid)
            {
                builder.AppendFormat("C:{0}", ConformanceDescriptor);
            }
            if (VarianceDescriptor.IsValid)
            {
                builder.AppendFormat("V:{0}", VarianceDescriptor);
            }

            if (builder.Length > 0)
            {
                return $"{context.FormatComment(builder.ToString())} {base.FormatType(context)}";
            }
            return base.FormatType(context);
        }
    }

    [Serializable]
    public sealed class NdrBogusArrayTypeReference : NdrBaseArrayTypeReference
    {
        public int NumberofElements { get; }
        public NdrCorrelationDescriptor ConformanceDescriptor { get; }
        public NdrCorrelationDescriptor VarianceDescriptor { get; }

        internal NdrBogusArrayTypeReference(NdrParseContext context, BinaryReader reader)
            : base(context, NdrFormatCharacter.FC_BOGUS_ARRAY, reader)
        {
            NumberofElements = reader.ReadInt16();
            ConformanceDescriptor = new NdrCorrelationDescriptor(context, reader);
            VarianceDescriptor = new NdrCorrelationDescriptor(context, reader);
            ReadElementType(context, reader);
        }

        protected override int GetElementCount()
        {
            if (NumberofElements > 0)
            {
                return NumberofElements;
            }

            if (VarianceDescriptor.IsConstant)
            {
                return VarianceDescriptor.Offset;
            }

            if (ConformanceDescriptor.IsConstant)
            {
                return ConformanceDescriptor.Offset;
            }

            return 0;
        }

        internal override string FormatType(INdrFormatterInternal context)
        {
            StringBuilder builder = new StringBuilder();
            if (ConformanceDescriptor != null && ConformanceDescriptor.IsValid)
            {
                builder.AppendFormat("C:{0}", ConformanceDescriptor);
            }
            if (VarianceDescriptor != null && VarianceDescriptor.IsValid)
            {
                builder.AppendFormat("V:{0}", VarianceDescriptor);
            }

            if (builder.Length > 0)
            {
                return $"{context.FormatComment(builder.ToString())} {base.FormatType(context)}";
            }
            return base.FormatType(context);
        }
    }

    [Serializable]
    public sealed class NdrVaryingArrayTypeReference : NdrBaseArrayTypeReference
    {
        private readonly int _element_size;

        public int TotalSize { get; }
        public int NumberofElements { get; }
        public NdrCorrelationDescriptor VarianceDescriptor { get; }

        internal NdrVaryingArrayTypeReference(NdrParseContext context, NdrFormatCharacter format, BinaryReader reader)
            : base(context, format, reader)
        {
            if (format == NdrFormatCharacter.FC_SMVARRAY)
            {
                TotalSize = reader.ReadUInt16();
                NumberofElements = reader.ReadUInt16();
            }
            else
            {
                TotalSize = reader.ReadInt32();
                NumberofElements = reader.ReadInt32();
            }

            _element_size = reader.ReadUInt16();
            VarianceDescriptor = new NdrCorrelationDescriptor(context, reader);
            ReadElementType(context, reader);
        }

        protected override int GetElementSize()
        {
            return _element_size;
        }

        protected override int GetElementCount()
        {
            if (NumberofElements > 0)
            {
                return NumberofElements;
            }

            if (VarianceDescriptor != null
                && VarianceDescriptor.CorrelationType == NdrCorrelationType.FC_CONSTANT_CONFORMANCE)
            {
                return VarianceDescriptor.Offset;
            }

            return 0;
        }

        internal override string FormatType(INdrFormatterInternal context)
        {
            StringBuilder builder = new StringBuilder();
            if (VarianceDescriptor != null && VarianceDescriptor.IsValid)
            {
                builder.AppendFormat("V:{0}", VarianceDescriptor);
            }

            if (builder.Length > 0)
            {
                return $"{context.FormatComment(builder.ToString())} {base.FormatType(context)}";
            }
            return base.FormatType(context);
        }
    }
#pragma warning restore 1591
}
