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

    [Flags]
    [Serializable]
    public enum NdrPointerFlags : byte
    {
        FC_ALLOCATE_ALL_NODES = 0x01,
        FC_DONT_FREE = 0x02,
        FC_ALLOCED_ON_STACK = 0x04,
        FC_SIMPLE_POINTER = 0x08,
        FC_POINTER_DEREF = 0x10,
        FC_MAYBE_NULL_SIZEIS = 0x20,
    }

    [Serializable]
    public class NdrInterfacePointerTypeReference : NdrBaseTypeReference
    {
        public Guid Iid { get; }

        public bool IsConstant { get; }

        public NdrCorrelationDescriptor IidIsDescriptor { get; }

        internal NdrInterfacePointerTypeReference(NdrParseContext context, BinaryReader reader) : base(NdrFormatCharacter.FC_IP)
        {
            NdrFormatCharacter type = ReadFormat(reader);
            if (type == NdrFormatCharacter.FC_CONSTANT_IID)
            {
                Iid = new Guid(reader.ReadAll(16));
                IsConstant = true;
            }
            else
            {
                Iid = NdrNativeUtils.IID_IUnknown;
                IidIsDescriptor = new NdrCorrelationDescriptor(context, reader);
            }
        }

        internal override string FormatType(INdrFormatterInternal formatter)
        {
            if (IsConstant)
            {
                string name = formatter.IidToName(Iid);
                if (name != null)
                {
                    return formatter.FormatPointer(name);
                }
                return $"{formatter.FormatComment("Unknown IID: {0}", Iid)} {formatter.FormatPointer("IUnknown")}";
            }
            else
            {
                return $"{formatter.FormatComment("iid_is param offset: {0}", IidIsDescriptor.Offset)} {formatter.FormatPointer("IUnknown")}";
            }
        }

        public override int GetSize()
        {
            return IntPtr.Size;
        }
    }

    [Serializable]
    public sealed class NdrPointerTypeReference : NdrBaseTypeReference
    {
        public NdrBaseTypeReference Type { get; private set; }
        public NdrPointerFlags Flags { get; }

        internal NdrPointerTypeReference(NdrBaseTypeReference type)
            : base(NdrFormatCharacter.FC_POINTER)
        {
            Type = type;
            Flags = NdrPointerFlags.FC_SIMPLE_POINTER;
        }

        internal NdrPointerTypeReference(NdrParseContext context, NdrFormatCharacter format, BinaryReader reader) : base(format)
        {
            Flags = (NdrPointerFlags)reader.ReadByte();
            if ((Flags & NdrPointerFlags.FC_SIMPLE_POINTER) == NdrPointerFlags.FC_SIMPLE_POINTER)
            {
                Type = new NdrSimpleTypeReference(ReadFormat(reader));
            }
            else
            {
                Type = Read(context, ReadTypeOffset(reader));
            }
        }

        internal override string FormatType(INdrFormatterInternal formatter)
        {
            if (Type is NdrBaseArrayTypeReference)
            {
                return Type.FormatType(formatter);
            }
            else
            {
                bool is_unique = Format == NdrFormatCharacter.FC_UP;
                return $"{(is_unique ? formatter.FormatComment("unique") : "")}{Type.FormatType(formatter)}*";
            }
        }

        public override int GetSize()
        {
            return IntPtr.Size;
        }

        protected override void OnFixupLateBoundTypes()
        {
            Type = GetIndirectType(Type);
        }
    }

    [Serializable]
    public sealed class NdrByteCountPointerReferenceType : NdrBaseTypeReference
    {
        public NdrBaseTypeReference Type { get; private set; }
        public NdrCorrelationDescriptor Description { get; private set; }

        internal NdrByteCountPointerReferenceType(NdrParseContext context, BinaryReader reader) : base(NdrFormatCharacter.FC_BYTE_COUNT_POINTER)
        {
            NdrFormatCharacter format = (NdrFormatCharacter)reader.ReadByte();
            if (format != NdrFormatCharacter.FC_PAD)
            {
                Type = new NdrSimpleTypeReference(format);
                Description = new NdrCorrelationDescriptor();
            }
            else
            {
                Description = new NdrCorrelationDescriptor(context, reader);
                Type = Read(context, ReadTypeOffset(reader));
            }
        }

        internal override string FormatType(INdrFormatterInternal context)
        {
            string comment = Format.ToString();
            if (Description.IsValid)
            {
                comment = $"{comment} {Description}";
            }
            return $"{context.FormatComment(comment)} {Type.FormatType(context)}*";
        }
    }
#pragma warning restore 1591
}
