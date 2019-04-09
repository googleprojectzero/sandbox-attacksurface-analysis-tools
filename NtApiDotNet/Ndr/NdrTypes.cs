//  Copyright 2018 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet.Ndr
{
#pragma warning disable 1591
    /// <summary>
    /// NDR format character.
    /// </summary>
    [Serializable]
    public enum NdrFormatCharacter : byte
    {
        FC_ZERO,
        FC_BYTE,                    // 0x01
        FC_CHAR,                    // 0x02
        FC_SMALL,                   // 0x03
        FC_USMALL,                  // 0x04
        FC_WCHAR,                   // 0x05
        FC_SHORT,                   // 0x06
        FC_USHORT,                  // 0x07
        FC_LONG,                    // 0x08
        FC_ULONG,                   // 0x09
        FC_FLOAT,                   // 0x0a
        FC_HYPER,                   // 0x0b
        FC_DOUBLE,                  // 0x0c
        FC_ENUM16,                  // 0x0d
        FC_ENUM32,                  // 0x0e
        FC_IGNORE,                  // 0x0f
        FC_ERROR_STATUS_T,          // 0x10
        FC_RP,                      // 0x11
        FC_UP,                      // 0x12
        FC_OP,                      // 0x13
        FC_FP,                      // 0x14
        FC_STRUCT,                  // 0x15
        FC_PSTRUCT,                 // 0x16
        FC_CSTRUCT,                 // 0x17
        FC_CPSTRUCT,                // 0x18
        FC_CVSTRUCT,                // 0x19
        FC_BOGUS_STRUCT,            // 0x1a
        FC_CARRAY,                  // 0x1b
        FC_CVARRAY,                 // 0x1c
        FC_SMFARRAY,                // 0x1d
        FC_LGFARRAY,                // 0x1e
        FC_SMVARRAY,                // 0x1f
        FC_LGVARRAY,                // 0x20
        FC_BOGUS_ARRAY,             // 0x21
        FC_C_CSTRING,               // 0x22
        FC_C_BSTRING,               // 0x23
        FC_C_SSTRING,               // 0x24
        FC_C_WSTRING,               // 0x25
        FC_CSTRING,                 // 0x26
        FC_BSTRING,                 // 0x27
        FC_SSTRING,                 // 0x28
        FC_WSTRING,                 // 0x29
        FC_ENCAPSULATED_UNION,      // 0x2a
        FC_NON_ENCAPSULATED_UNION,  // 0x2b
        FC_BYTE_COUNT_POINTER,      // 0x2c
        FC_TRANSMIT_AS,             // 0x2d
        FC_REPRESENT_AS,            // 0x2e
        FC_IP,                      // 0x2f
        FC_BIND_CONTEXT,            // 0x30
        FC_BIND_GENERIC,            // 0x31
        FC_BIND_PRIMITIVE,          // 0x32
        FC_AUTO_HANDLE,             // 0x33
        FC_CALLBACK_HANDLE,         // 0x34
        FC_UNUSED1,                 // 0x35
        FC_POINTER,                 // 0x36
        FC_ALIGNM2,                 // 0x37
        FC_ALIGNM4,                 // 0x38
        FC_ALIGNM8,                 // 0x39
        FC_UNUSED2,                 // 0x3a
        FC_UNUSED3,                 // 0x3b
        FC_SYSTEM_HANDLE,           // 0x3c (was FC_UNUSED4)
        FC_STRUCTPAD1,              // 0x3d
        FC_STRUCTPAD2,              // 0x3e
        FC_STRUCTPAD3,              // 0x3f
        FC_STRUCTPAD4,              // 0x40
        FC_STRUCTPAD5,              // 0x41
        FC_STRUCTPAD6,              // 0x42
        FC_STRUCTPAD7,              // 0x43
        FC_STRING_SIZED,            // 0x44
        FC_UNUSED5,                 // 0x45
        FC_NO_REPEAT,               // 0x46
        FC_FIXED_REPEAT,            // 0x47
        FC_VARIABLE_REPEAT,         // 0x48
        FC_FIXED_OFFSET,            // 0x49
        FC_VARIABLE_OFFSET,         // 0x4a
        FC_PP,                      // 0x4b
        FC_EMBEDDED_COMPLEX,        // 0x4c
        FC_IN_PARAM,                // 0x4d
        FC_IN_PARAM_BASETYPE,       // 0x4e
        FC_IN_PARAM_NO_FREE_INST,   // 0x4d
        FC_IN_OUT_PARAM,            // 0x50
        FC_OUT_PARAM,               // 0x51
        FC_RETURN_PARAM,            // 0x52
        FC_RETURN_PARAM_BASETYPE,   // 0x53
        FC_DEREFERENCE,             // 0x54
        FC_DIV_2,                   // 0x55
        FC_MULT_2,                  // 0x56
        FC_ADD_1,                   // 0x57
        FC_SUB_1,                   // 0x58
        FC_CALLBACK,                // 0x59
        FC_CONSTANT_IID,            // 0x5a
        FC_END,                     // 0x5b
        FC_PAD,                     // 0x5c
        FC_SPLIT_DEREFERENCE = 0x74,      // 0x74
        FC_SPLIT_DIV_2,                   // 0x75
        FC_SPLIT_MULT_2,                  // 0x76
        FC_SPLIT_ADD_1,                   // 0x77
        FC_SPLIT_SUB_1,                   // 0x78
        FC_SPLIT_CALLBACK,                // 0x79
        FC_FORCED_BOGUS_STRUCT = 0xb1,      // 0xb1 - Seemed to originally be FC_HARD_STRUCT.
        FC_TRANSMIT_AS_PTR,         // 0xb2
        FC_REPRESENT_AS_PTR,        // 0xb3
        FC_USER_MARSHAL,            // 0xb4
        FC_PIPE,                    // 0xb5
        FC_SUPPLEMENT,                 // 0xb6 - Seemed to originally be FC_BLKHOLE.
        FC_RANGE,                   // 0xb7
        FC_INT3264,                 // 0xb8
        FC_UINT3264,                // 0xb9
        FC_END_OF_UNIVERSE          // 0xba
    }

    [Flags]
    [Serializable]
    public enum NdrBlackholeFlags
    {
        None = 0,
        BaseType = 0x1,
        Function = 0x2,
        XurType = 0x4,  // Xmit Usermarshal or Represent-as TYPE
    }

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

    [Flags]
    [Serializable]
    public enum NdrUserMarshalFlags : byte
    {
        USER_MARSHAL_POINTER = 0xc0,
        USER_MARSHAL_UNIQUE = 0x80,
        USER_MARSHAL_REF = 0x40,
        USER_MARSHAL_IID = 0x20
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

        internal override string FormatType(NdrFormatter formatter)
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
    }

    [Serializable]
    public class NdrPointerTypeReference : NdrBaseTypeReference
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

        internal override string FormatType(NdrFormatter formatter)
        {
            if (Type is NdrBaseArrayTypeReference)
            {
                return Type.FormatType(formatter);
            }
            else
            {
                bool is_unique = Format == NdrFormatCharacter.FC_UP;
                return string.Format("{0}{1}*", is_unique ? formatter.FormatComment("unique") : "", Type.FormatType(formatter));
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

    // Marker class for a string type.
    [Serializable]
    public class NdrBaseStringTypeReference : NdrBaseTypeReference
    {
        internal NdrBaseStringTypeReference(NdrFormatCharacter format) : base(format)
        {
        }
    }

    [Serializable]
    public class NdrStringTypeReference : NdrBaseStringTypeReference
    {
        public int StringSize { get; }

        internal NdrStringTypeReference(NdrFormatCharacter format, BinaryReader reader) : base(format)
        {
            reader.ReadByte(); // Padding.
            StringSize = reader.ReadUInt16();
        }

        internal override string FormatType(NdrFormatter context)
        {
            if (StringSize > 0)
            {
                return string.Format("{0}[{1}]", base.FormatType(context), StringSize);
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
    public class NdrConformantStringTypeReference : NdrBaseStringTypeReference
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

        internal override string FormatType(NdrFormatter context)
        {
            string conformance_desc = string.Empty;
            if (ConformanceDescriptor != null && ConformanceDescriptor.IsValid)
            {
                conformance_desc = context.FormatComment(ConformanceDescriptor.ToString());
            }

            if (!ConformanceDescriptor.IsValid)
            {
                return string.Format("{0}{1}", conformance_desc, base.FormatType(context));
            }

            return string.Format("{0}{1}[{2}]", conformance_desc, base.FormatType(context), GetCharCount());
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
    public class NdrStructureStringTypeReferece : NdrBaseStringTypeReference
    {
        public int ElementSize { get; }
        public int NumberOfElements { get; }
        internal NdrStructureStringTypeReferece(NdrFormatCharacter format, BinaryReader reader) : base(format)
        {
            ElementSize = reader.ReadByte();
            if (format == NdrFormatCharacter.FC_SSTRING)
            {
                NumberOfElements = reader.ReadUInt16();
            }
        }

        internal override string FormatType(NdrFormatter formatter)
        {
            return string.Format("{0}<{1}>[{2}]", base.FormatType(formatter), ElementSize, NumberOfElements);
        }
    }

    [Serializable]
    public class NdrUserMarshalTypeReference : NdrBaseTypeReference
    {
        public NdrUserMarshalFlags Flags { get; }
        public int QuadrupleIndex { get; }
        public int UserTypeMemorySite { get; }
        public int TransmittedTypeBufferSize { get; }
        public NdrBaseTypeReference Type { get; }

        internal NdrUserMarshalTypeReference(NdrParseContext context, BinaryReader reader)
            : base(NdrFormatCharacter.FC_USER_MARSHAL)
        {
            Flags = (NdrUserMarshalFlags)(reader.ReadByte() & 0xF0);
            QuadrupleIndex = reader.ReadUInt16();
            UserTypeMemorySite = reader.ReadUInt16();
            TransmittedTypeBufferSize = reader.ReadUInt16();
            Type = Read(context, ReadTypeOffset(reader));
        }

        internal override string FormatType(NdrFormatter formatter)
        {
            if ((Flags & NdrUserMarshalFlags.USER_MARSHAL_POINTER) != 0)
            {
                return formatter.FormatPointer(base.FormatType(formatter));
            }
            return base.FormatType(formatter);
        }
    }

    [Serializable]
    public enum NdrKnownTypes
    {
        None,

        // OLEAUT32
        BSTR,
        LPSAFEARRAY,
        VARIANT,
        HWND,
        GUID,

        // OLE32
        HENHMETAFILE,
        HMETAFILEPICT,
        HMETAFILE,
        SNB,
        STGMEDIUM,

        // COMBASE
        CLIPFORMAT,
        HACCEL,
        HBITMAP,
        HBRUSH,
        HDC,
        HGLOBAL,
        HICON,
        HMENU,
        HMONITOR,
        HPALETTE,
        HRGN,
        HSTRING,
        WdtpInterfacePointer,
    }

    [Serializable]
    public class NdrNamedTypeReference : NdrBaseTypeReference
    {
        public string Name { get; }

        public NdrNamedTypeReference(string name)
            : base(NdrFormatCharacter.FC_USER_MARSHAL)
        {
            Name = name;
        }

        internal override string FormatType(NdrFormatter formatter)
        {
            return Name;
        }

        public override int GetSize()
        {
            // We don't really know how big this type is, so just return pointer sized.
            return IntPtr.Size;
        }
    }

    [Serializable]
    public class NdrKnownTypeReference : NdrBaseTypeReference
    {
        public NdrKnownTypes KnownType { get; }

        public NdrKnownTypeReference(NdrKnownTypes type)
            : base(NdrFormatCharacter.FC_USER_MARSHAL)
        {
            KnownType = type;
        }

        internal override string FormatType(NdrFormatter formatter)
        {
            return KnownType.ToString();
        }

        public override int GetSize()
        {
            switch (KnownType)
            {
                case NdrKnownTypes.GUID:
                    return 16;
                case NdrKnownTypes.BSTR:
                case NdrKnownTypes.LPSAFEARRAY:
                case NdrKnownTypes.HWND:
                case NdrKnownTypes.HENHMETAFILE:
                case NdrKnownTypes.HMETAFILEPICT:
                case NdrKnownTypes.HMETAFILE:
                case NdrKnownTypes.HACCEL:
                case NdrKnownTypes.HBITMAP:
                case NdrKnownTypes.HBRUSH:
                case NdrKnownTypes.HDC:
                case NdrKnownTypes.HGLOBAL:
                case NdrKnownTypes.HICON:
                case NdrKnownTypes.HMENU:
                case NdrKnownTypes.HMONITOR:
                case NdrKnownTypes.HPALETTE:
                case NdrKnownTypes.HRGN:
                case NdrKnownTypes.HSTRING:
                case NdrKnownTypes.WdtpInterfacePointer:
                    return IntPtr.Size;
                case NdrKnownTypes.VARIANT:
                    return Environment.Is64BitProcess ? 24 : 16;
                case NdrKnownTypes.SNB:
                case NdrKnownTypes.CLIPFORMAT:
                    return 4;
                case NdrKnownTypes.STGMEDIUM:
                    return Environment.Is64BitProcess ? 24 : 12;
                default:
                    throw new ArgumentException("Unknown Known Type");
            }
        }
    }

    [Serializable]
    public class NdrUnknownTypeReference : NdrBaseTypeReference
    {
        static HashSet<NdrFormatCharacter> _formats = new HashSet<NdrFormatCharacter>();
        internal NdrUnknownTypeReference(NdrFormatCharacter format) : base(format)
        {
            if (_formats.Add(format))
            {
                System.Diagnostics.Debug.WriteLine(format.ToString());
            }
        }

        internal override string FormatType(NdrFormatter formatter)
        {
            return $"{formatter.FormatComment("Unhandled")} {base.FormatType(formatter)}";
        }
    }

    [Serializable]
    public class NdrStructureMember
    {
        public NdrBaseTypeReference MemberType { get; internal set; }
        public int Offset { get; private set; }
        public string Name { get; set; }

        internal NdrStructureMember(NdrBaseTypeReference member_type, int offset, string name)
        {
            MemberType = member_type;
            Offset = offset;
            Name = name;
        }

        internal string FormatMember(NdrFormatter context)
        {
            return string.Format("{0} {1}", context.FormatComment("Offset: {0}", Offset), MemberType.FormatType(context));
        }

        internal void FixupLateBoundTypes()
        {
            MemberType = NdrBaseTypeReference.GetIndirectType(MemberType);
        }
    }

    [Serializable]
    public class NdrBaseStructureTypeReference : NdrComplexTypeReference
    {
        protected List<NdrBaseTypeReference> _base_members;
        private List<NdrStructureMember> _members;

        public int Alignment { get; }
        public int MemorySize { get; }

        protected virtual List<NdrStructureMember> PopulateMembers()
        {
            List<NdrStructureMember> members = new List<NdrStructureMember>();
            int current_offset = 0;
            foreach (var type in _base_members)
            {
                if (!(type is NdrStructurePaddingTypeReference))
                {
                    members.Add(new NdrStructureMember(type, current_offset, $"Member{current_offset:X}"));
                }
                current_offset += type.GetSize();
            }
            return members;
        }

        private List<NdrStructureMember> GetMembers()
        {
            if (_members == null)
            {
                _members = PopulateMembers();
            }
            return _members;
        }

        public IEnumerable<NdrBaseTypeReference> MembersTypes { get { return _base_members.AsReadOnly(); } }

        public IEnumerable<NdrStructureMember> Members => GetMembers().AsReadOnly();

        internal NdrBaseStructureTypeReference(NdrParseContext context, NdrFormatCharacter format, BinaryReader reader)
            : base($"Struct_{context.TypeCache.GetNextComplexId()}", format)
        {
            Alignment = reader.ReadByte();
            MemorySize = reader.ReadUInt16();
            _base_members = new List<NdrBaseTypeReference>();
        }

        internal void ReadMemberInfo(NdrParseContext context, BinaryReader reader)
        {
            NdrBaseTypeReference curr_type;
            while ((curr_type = Read(context, reader)) != null)
            {
                _base_members.Add(curr_type);
            }
        }

        internal override string FormatType(NdrFormatter context)
        {
            return $"struct {Name}";
        }

        internal override string FormatComplexType(NdrFormatter context)
        {
            StringBuilder builder = new StringBuilder();
            builder.Append(context.FormatComment("Memory Size: {0}", GetSize())).AppendLine();
            builder.Append(FormatType(context)).AppendLine(" {");
            foreach (var member in Members.Select((m, i) => $"{m.FormatMember(context)} {m.Name}"))
            {
                builder.Append("    ").Append(member).AppendLine(";");
            }
            builder.AppendLine("};");
            return builder.ToString();
        }

        public override int GetSize()
        {
            return MemorySize;
        }

        protected override void OnFixupLateBoundTypes()
        {
            foreach (var member in _base_members)
            {
                member.FixupLateBoundTypes();
            }
        }
    }

    [Serializable]
    public class NdrSimpleStructureTypeReference : NdrBaseStructureTypeReference
    {
        internal NdrSimpleStructureTypeReference(NdrParseContext context, BinaryReader reader)
            : base(context, NdrFormatCharacter.FC_STRUCT, reader)
        {
            ReadMemberInfo(context, reader);
        }
    }

    [Serializable]
    public class NdrSimpleStructureWithPointersTypeReference : NdrBaseStructureTypeReference
    {
        public NdrPointerInfoTypeReference PointerInfo { get; }

        internal NdrSimpleStructureWithPointersTypeReference(NdrParseContext context, BinaryReader reader)
            : base(context, NdrFormatCharacter.FC_PSTRUCT, reader)
        {
            // Read out FC_PP type.
            reader.ReadByte();
            PointerInfo = new NdrPointerInfoTypeReference(context, reader);
            ReadMemberInfo(context, reader);
        }

        protected override List<NdrStructureMember> PopulateMembers()
        {
            var members = base.PopulateMembers();
            var pointer_types = PointerInfo.PointerInstances.ToDictionary(p => p.OffsetInMemory);

            foreach (var member in members)
            {
                if (pointer_types.ContainsKey(member.Offset))
                {
                    member.MemberType = pointer_types[member.Offset].PointerType;
                }
            }

            return members;
        }
    }

    [Serializable]
    public class NdrConformantStructureTypeReference : NdrBaseStructureTypeReference
    {
        internal NdrConformantStructureTypeReference(NdrParseContext context, BinaryReader reader)
            : base(context, NdrFormatCharacter.FC_CSTRUCT, reader)
        {
            NdrBaseTypeReference array = Read(context, ReadTypeOffset(reader));
            ReadMemberInfo(context, reader);
            if (array != null)
            {
                _base_members.Add(array);
            }
        }
    }

    [Serializable]
    public class NdrBogusStructureTypeReference : NdrBaseStructureTypeReference
    {
        internal NdrBogusStructureTypeReference(NdrParseContext context, NdrFormatCharacter format, BinaryReader reader)
            : base(context, format, reader)
        {
            NdrBaseTypeReference array = Read(context, ReadTypeOffset(reader));
            int pointer_ofs = ReadTypeOffset(reader);
            ReadMemberInfo(context, reader);
            if (pointer_ofs >= 0)
            {
                BinaryReader pointer_reader = GetReader(context, pointer_ofs);
                for (int i = 0; i < _base_members.Count; ++i)
                {
                    if (_base_members[i].Format == NdrFormatCharacter.FC_POINTER)
                    {
                        _base_members[i] = Read(context, reader);
                    }
                }
            }

            if (array != null)
            {
                _base_members.Add(array);
            }
        }
    }

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

        internal override string FormatType(NdrFormatter context)
        {
            return string.Format("{0}[{1}]", ElementType.FormatType(context), ElementCount == 0 ? string.Empty : ElementCount.ToString());
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
            ReadElementType(context, reader);
        }

        protected override int GetElementSize()
        {
            return _element_size;
        }

        protected override int GetElementCount()
        {
            if (VarianceDescriptor != null
                && VarianceDescriptor.CorrelationType == NdrCorrelationType.FC_CONSTANT_CONFORMANCE)
            {
                return VarianceDescriptor.Offset;
            }

            if (ConformanceDescriptor != null
                && ConformanceDescriptor.CorrelationType == NdrCorrelationType.FC_CONSTANT_CONFORMANCE)
            {
                return ConformanceDescriptor.Offset;
            }

            return 0;
        }

        internal override string FormatType(NdrFormatter context)
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

        internal override string FormatType(NdrFormatter context)
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

        internal override string FormatType(NdrFormatter context)
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

    [Serializable]
    public class NdrStructurePaddingTypeReference : NdrBaseTypeReference
    {
        internal NdrStructurePaddingTypeReference(NdrFormatCharacter format) : base(format)
        {
        }

        public override int GetSize()
        {
            switch (Format)
            {
                case NdrFormatCharacter.FC_STRUCTPAD1:
                    return 1;
                case NdrFormatCharacter.FC_STRUCTPAD2:
                    return 2;
                case NdrFormatCharacter.FC_STRUCTPAD3:
                    return 3;
                case NdrFormatCharacter.FC_STRUCTPAD4:
                    return 4;
                case NdrFormatCharacter.FC_STRUCTPAD5:
                    return 5;
                case NdrFormatCharacter.FC_STRUCTPAD6:
                    return 6;
                case NdrFormatCharacter.FC_STRUCTPAD7:
                    return 7;
                default:
                    throw new InvalidOperationException("Format must be a padding character");
            }
        }
    }

    [Serializable]
    public class NdrPointerInfoInstance
    {
        public int OffsetInMemory { get; }
        public int OffsetInBuffer { get; }
        public NdrPointerTypeReference PointerType { get; }

        internal NdrPointerInfoInstance(NdrParseContext context, BinaryReader reader)
        {
            OffsetInMemory = reader.ReadInt16();
            OffsetInBuffer = reader.ReadInt16();
            PointerType = NdrBaseTypeReference.Read(context, reader) as NdrPointerTypeReference;
        }
    }

    [Serializable]
    public class NdrPointerInfoTypeReference : NdrBaseTypeReference
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
            List<NdrPointerInfoInstance> instances = new List<NdrPointerInfoInstance>();
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
    }

    [Serializable]
    public class NdrRangeTypeReference : NdrBaseTypeReference
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

        internal override string FormatType(NdrFormatter context)
        {
            return string.Format("{0} {1}", context.FormatComment("range: {0},{1}", MinValue, MaxValue), RangeType.FormatType(context));
        }

        public override int GetSize()
        {
            return RangeType.GetSize();
        }
    }

    [Serializable]
    public class NdrIndirectTypeReference : NdrBaseTypeReference
    {
        public NdrBaseTypeReference RefType { get; private set; }

        internal void FixupType(NdrBaseTypeReference ref_type)
        {
            RefType = ref_type;
        }

        internal NdrIndirectTypeReference() : base(NdrFormatCharacter.FC_ZERO)
        {
        }

        internal override string FormatType(NdrFormatter context)
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
    public abstract class NdrComplexTypeReference : NdrBaseTypeReference
    {
        public string Name { get; set; }
        internal abstract string FormatComplexType(NdrFormatter context);

        internal NdrComplexTypeReference(string name, NdrFormatCharacter format) : base(format)
        {
            Name = name;
        }
    }

    [Serializable]
    public sealed class NdrUnionTypeReference : NdrComplexTypeReference
    {
        public NdrFormatCharacter SwitchType { get; }
        public int SwitchIncrement { get; }
        public NdrUnionArms Arms { get; }
        public NdrCorrelationDescriptor Correlation { get; }

        internal NdrUnionTypeReference(NdrFormatCharacter format, NdrParseContext context, BinaryReader reader)
            : base($"Union_{context.TypeCache.GetNextComplexId()}", format)
        {
            int switch_type = reader.ReadByte();
            SwitchIncrement = (switch_type >> 4) & 0xF;
            SwitchType = (NdrFormatCharacter)(switch_type & 0xF);

            if (format == NdrFormatCharacter.FC_NON_ENCAPSULATED_UNION)
            {
                Correlation = new NdrCorrelationDescriptor(context, reader);
                Arms = new NdrUnionArms(context, ReadTypeOffset(reader));
            }
            else
            {
                Arms = new NdrUnionArms(context, reader);
            }
        }

        internal override string FormatType(NdrFormatter context)
        {
            return string.Format("{0} {1}",
                 Format == NdrFormatCharacter.FC_NON_ENCAPSULATED_UNION ? "union" : "struct",
                 Name);
        }

        internal override string FormatComplexType(NdrFormatter context)
        {
            int indent = 4;
            StringBuilder builder = new StringBuilder();
            builder.Append(context.FormatComment("Memory Size: {0}", GetSize())).AppendLine();
            builder.Append(FormatType(context)).AppendLine(" {");

            if (Format == NdrFormatCharacter.FC_ENCAPSULATED_UNION)
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

            if (Format == NdrFormatCharacter.FC_ENCAPSULATED_UNION)
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

    [Serializable]
    public enum NdrSystemHandleResource
    {
        File = 0,
        Semaphore = 1,
        Event = 2,
        Mutex = 3,
        Process = 4,
        Token = 5,
        Section = 6,
        RegKey = 7,
        Thread = 8,
        Composition = 9,
        Socket = 10,
        Job = 11,
        Pipe = 12
    }

    [Serializable]
    public sealed class NdrSystemHandleTypeReference : NdrBaseTypeReference
    {
        // IDL is [system_handle(sh_file, 0x1234)]HANDLE

        public NdrSystemHandleResource Resource { get; }
        public uint AccessMask { get; }

        internal NdrSystemHandleTypeReference(BinaryReader reader)
            : base(NdrFormatCharacter.FC_SYSTEM_HANDLE)
        {
            Resource = (NdrSystemHandleResource)reader.ReadByte();
            AccessMask = reader.ReadUInt32();
        }

        internal override string FormatType(NdrFormatter context)
        {
            if (AccessMask != 0)
            {
                object access = null;
                switch (Resource)
                {
                    case NdrSystemHandleResource.Pipe:
                    case NdrSystemHandleResource.File:
                        access = (FileAccessRights)AccessMask;
                        break;
                    case NdrSystemHandleResource.Process:
                        access = (ProcessAccessRights)AccessMask;
                        break;
                    case NdrSystemHandleResource.Thread:
                        access = (ThreadAccessRights)AccessMask;
                        break;
                    case NdrSystemHandleResource.Event:
                        access = (EventAccessRights)AccessMask;
                        break;
                    case NdrSystemHandleResource.Job:
                        access = (JobAccessRights)AccessMask;
                        break;
                    case NdrSystemHandleResource.Mutex:
                        access = (MutantAccessRights)AccessMask;
                        break;
                    case NdrSystemHandleResource.RegKey:
                        access = (KeyAccessRights)AccessMask;
                        break;
                    case NdrSystemHandleResource.Section:
                        access = (SectionAccessRights)AccessMask;
                        break;
                    case NdrSystemHandleResource.Semaphore:
                        access = (SemaphoreAccessRights)AccessMask;
                        break;
                    case NdrSystemHandleResource.Token:
                        access = (TokenAccessRights)AccessMask;
                        break;
                    default:
                        access = string.Format("0x{0:X}", AccessMask);
                        break;
                }

                return string.Format("{0} HANDLE", context.FormatComment("FC_SYSTEM_HANDLE {0}({1})", Resource, access));
            }
            return string.Format("{0} HANDLE", context.FormatComment("FC_SYSTEM_HANDLE {0}", Resource));
        }

        public override int GetSize()
        {
            return IntPtr.Size;
        }
    }

    [Serializable]
    public class NdrHandleTypeReference : NdrBaseTypeReference
    {
        internal NdrHandleTypeReference(NdrFormatCharacter format)
            : base(format)
        {
        }

        internal override string FormatType(NdrFormatter context)
        {
            return $"{context.FormatComment(Format.ToString())} {context.SimpleTypeToName(Format)}";
        }
    }

    [Serializable]
    public class NdrPipeTypeReference : NdrBaseTypeReference
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

        internal override string FormatType(NdrFormatter context)
        {
            return $"{context.FormatComment("FC_PIPE")} {BaseType.FormatType(context)}";
        }

        public override int GetSize()
        {
            return BaseType.GetSize();
        }
    }

    [Serializable]
    public class NdrBlkHoleTypeReference : NdrBaseTypeReference
    {
        public NdrBlackholeFlags Flags { get; }

        internal NdrBlkHoleTypeReference(NdrParseContext context, BinaryReader reader)
            : base(NdrFormatCharacter.FC_SUPPLEMENT)
        {
            Flags = (NdrBlackholeFlags)reader.ReadByte();
        }

        internal override string FormatType(NdrFormatter context)
        {
            return $"{context.FormatComment($"FC_SUPPLEMENT {Flags}")} void";
        }

        public override int GetSize()
        {
            return IntPtr.Size;
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

        internal override string FormatType(NdrFormatter context)
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

    [Serializable]
    public abstract class NdrBaseTypeReference
    {
        public NdrFormatCharacter Format { get; }

        protected NdrBaseTypeReference(NdrFormatCharacter format)
        {
            Format = format;
        }

        public override string ToString()
        {
            return string.Format("{0} - {1}", Format, GetType().Name);
        }

        internal virtual string FormatType(NdrFormatter context)
        {
            return context.SimpleTypeToName(Format);
        }

        internal static NdrFormatCharacter ReadFormat(BinaryReader reader)
        {
            return (NdrFormatCharacter)reader.ReadByte();
        }

        protected virtual void OnFixupLateBoundTypes()
        {
            // Do nothing in the base.
        }

        private bool _late_bound_types_fixed;

        internal static NdrBaseTypeReference GetIndirectType(NdrBaseTypeReference base_type)
        {
            if (base_type is NdrIndirectTypeReference type)
            {
                return type.RefType;
            }
            return base_type;
        }

        internal void FixupLateBoundTypes()
        {
            if (!_late_bound_types_fixed)
            {
                _late_bound_types_fixed = true;
                OnFixupLateBoundTypes();
            }
        }

        private class StandardUserMarshaler
        {
            public NdrKnownTypes KnownType { get; }
            public bool IsMatch(IntPtr ptr)
            {
                return ptr == _size_ptr || ptr == _size_64_ptr;
            }

            public StandardUserMarshaler(SafeLoadLibraryHandle lib, NdrKnownTypes known_type)
            {
                _size_ptr = lib.GetProcAddress(string.Format("{0}_UserSize", known_type));
                _size_64_ptr = lib.GetProcAddress(string.Format("{0}_UserSize64", known_type));
                KnownType = known_type;
            }

            private IntPtr _size_ptr;
            private IntPtr _size_64_ptr;
        }

        private class StandardUserMarshalers
        {
            List<StandardUserMarshaler> _marshalers;

            private void LoadMarshallersForComBase(SafeLoadLibraryHandle lib)
            {
                _marshalers.Add(new StandardUserMarshaler(lib, NdrKnownTypes.CLIPFORMAT));
                _marshalers.Add(new StandardUserMarshaler(lib, NdrKnownTypes.HACCEL));
                _marshalers.Add(new StandardUserMarshaler(lib, NdrKnownTypes.HBITMAP));
                _marshalers.Add(new StandardUserMarshaler(lib, NdrKnownTypes.HBRUSH));
                _marshalers.Add(new StandardUserMarshaler(lib, NdrKnownTypes.HDC));
                _marshalers.Add(new StandardUserMarshaler(lib, NdrKnownTypes.HGLOBAL));
                _marshalers.Add(new StandardUserMarshaler(lib, NdrKnownTypes.HICON));
                _marshalers.Add(new StandardUserMarshaler(lib, NdrKnownTypes.HMENU));
                _marshalers.Add(new StandardUserMarshaler(lib, NdrKnownTypes.HMONITOR));
                _marshalers.Add(new StandardUserMarshaler(lib, NdrKnownTypes.HPALETTE));
                _marshalers.Add(new StandardUserMarshaler(lib, NdrKnownTypes.HRGN));
                _marshalers.Add(new StandardUserMarshaler(lib, NdrKnownTypes.HSTRING));
                _marshalers.Add(new StandardUserMarshaler(lib, NdrKnownTypes.WdtpInterfacePointer));
            }

            public StandardUserMarshalers()
            {
                _marshalers = new List<StandardUserMarshaler>();
                using (var lib = SafeLoadLibraryHandle.LoadLibrary("oleaut32.dll"))
                {
                    _marshalers.Add(new StandardUserMarshaler(lib, NdrKnownTypes.BSTR));
                    _marshalers.Add(new StandardUserMarshaler(lib, NdrKnownTypes.VARIANT));
                    _marshalers.Add(new StandardUserMarshaler(lib, NdrKnownTypes.LPSAFEARRAY));
                    _marshalers.Add(new StandardUserMarshaler(lib, NdrKnownTypes.HWND));
                }

                using (var lib = SafeLoadLibraryHandle.LoadLibrary("ole32.dll"))
                {
                    _marshalers.Add(new StandardUserMarshaler(lib, NdrKnownTypes.HENHMETAFILE));
                    _marshalers.Add(new StandardUserMarshaler(lib, NdrKnownTypes.HMETAFILEPICT));
                    _marshalers.Add(new StandardUserMarshaler(lib, NdrKnownTypes.HMETAFILE));
                    _marshalers.Add(new StandardUserMarshaler(lib, NdrKnownTypes.SNB));
                    _marshalers.Add(new StandardUserMarshaler(lib, NdrKnownTypes.STGMEDIUM));
                    if (NtObjectUtils.IsWindows7OrLess)
                    {
                        LoadMarshallersForComBase(lib);
                    }
                }

                if (!NtObjectUtils.IsWindows7OrLess)
                {
                    using (var lib = SafeLoadLibraryHandle.LoadLibrary("combase.dll"))
                    {
                        LoadMarshallersForComBase(lib);
                    }
                }
            }

            public NdrKnownTypes GetKnownType(IntPtr ptr)
            {
                foreach (var marshaler in _marshalers)
                {
                    if (marshaler.IsMatch(ptr))
                    {
                        return marshaler.KnownType;
                    }
                }
                return NdrKnownTypes.None;
            }
        }

        private static StandardUserMarshalers m_marshalers;

        // Walk series of jumps until we either find an address we don't know or we change modules.
        internal static IntPtr GetTargetAddress(SafeLoadLibraryHandle curr_module, IntPtr ptr)
        {
            byte start_byte = Marshal.ReadByte(ptr);
            switch (start_byte)
            {
                // Absolute jump.
                case 0xFF:
                    if (Marshal.ReadByte(ptr + 1) != 0x25)
                    {
                        return ptr;
                    }

                    if (Environment.Is64BitProcess)
                    {
                        // RIP relative
                        ptr = Marshal.ReadIntPtr(ptr + 6 + Marshal.ReadInt32(ptr + 2));
                    }
                    else
                    {
                        // Absolute
                        ptr = Marshal.ReadIntPtr(new IntPtr(Marshal.ReadInt32(ptr + 2)));
                    }
                    break;
                // Relative jump.
                case 0xE9:
                    ptr = ptr + 5 + Marshal.ReadInt32(ptr + 1);
                    break;
                // lea rax, ofs import - Delay load 64bit
                case 0x48:
                    {
                        if (!Environment.Is64BitProcess || Marshal.ReadByte(ptr + 1) != 0x8D || Marshal.ReadByte(ptr + 2) != 0x05)
                        {
                            return ptr;
                        }
                        IntPtr iat = ptr + Marshal.ReadInt32(ptr + 3) + 7;
                        IDictionary<IntPtr, IntPtr> delayed_loaded = curr_module.ParseDelayedImports();
                        if (delayed_loaded.ContainsKey(iat))
                        {
                            return delayed_loaded[iat];
                        }
                        return ptr;
                    }
                // mov eax, ofs import - Delay load 32bit
                case 0xB8:
                    {
                        if (Environment.Is64BitProcess)
                        {
                            return ptr;
                        }
                        IntPtr iat = Marshal.ReadIntPtr(ptr + 1);
                        IDictionary<IntPtr, IntPtr> delayed_loaded = curr_module.ParseDelayedImports();
                        if (delayed_loaded.ContainsKey(iat))
                        {
                            return delayed_loaded[iat];
                        }
                        return ptr;
                    }
                default:
                    return ptr;
            }

            using (SafeLoadLibraryHandle lib = SafeLoadLibraryHandle.GetModuleHandle(ptr))
            {
                if (lib == null || lib.DangerousGetHandle() != curr_module.DangerousGetHandle())
                {
                    return ptr;
                }
            }

            return GetTargetAddress(curr_module, ptr);
        }

        private static NdrBaseTypeReference FixupUserMarshal(NdrParseContext context, NdrUserMarshalTypeReference type)
        {
            if (context.StubDesc.aUserMarshalQuadruple == IntPtr.Zero)
            {
                return type;
            }

            IntPtr marshal_ptr = context.Reader.ReadIntPtr(context.StubDesc.aUserMarshalQuadruple
                    + (type.QuadrupleIndex * context.Reader.PointerSize * 4));

            // If in process try and read out known type by walking pointers.
            if (context.Reader.InProcess && !context.HasFlag(NdrParserFlags.IgnoreUserMarshal))
            {
                using (var module = SafeLoadLibraryHandle.GetModuleHandle(context.StubDesc.aUserMarshalQuadruple))
                {
                    if (module == null)
                    {
                        return type;
                    }

                    if (m_marshalers == null)
                    {
                        m_marshalers = new StandardUserMarshalers();
                    }

                    NdrKnownTypes known_type = m_marshalers.GetKnownType(marshal_ptr);
                    if (known_type == NdrKnownTypes.None)
                    {
                        IntPtr usersize_ptr = GetTargetAddress(module, marshal_ptr);
                        known_type = m_marshalers.GetKnownType(usersize_ptr);
                    }

                    if (known_type != NdrKnownTypes.None)
                    {
                        return new NdrKnownTypeReference(known_type);
                    }
                }
            }

            // If we have a symbol resolver then see if we can get it from the symbol name.
            if (context.SymbolResolver != null)
            {
                string name = context.SymbolResolver.GetSymbolForAddress(marshal_ptr);
                int index = name.IndexOf("_UserSize", StringComparison.OrdinalIgnoreCase);
                if (index > 0)
                {
                    name = name.Substring(0, index);
                    if (Enum.TryParse(name.Substring(0, index), true, out NdrKnownTypes known_type)
                        && known_type != NdrKnownTypes.None)
                    {
                        return new NdrKnownTypeReference(known_type);
                    }
                    return new NdrNamedTypeReference(name);
                }
            }

            return type;
        }

        internal static NdrBaseTypeReference FixupSimpleStructureType(NdrSimpleStructureTypeReference type)
        {
            if (type.MemorySize == 16 &&
                type.MembersTypes.Count() == 4)
            {
                NdrBaseTypeReference[] members = type.MembersTypes.ToArray();
                if (members[0].Format == NdrFormatCharacter.FC_LONG
                    && members[1].Format == NdrFormatCharacter.FC_SHORT
                    && members[2].Format == NdrFormatCharacter.FC_SHORT
                    && members[3] is NdrSimpleArrayTypeReference)
                {
                    NdrSimpleArrayTypeReference array = members[3] as NdrSimpleArrayTypeReference;
                    if (array.TotalSize == 8 && array.ElementType.Format == NdrFormatCharacter.FC_BYTE)
                    {
                        return new NdrKnownTypeReference(NdrKnownTypes.GUID);
                    }
                }
            }

            return type;
        }

        internal static int ReadTypeOffset(BinaryReader reader)
        {
            long curr_ofs = reader.BaseStream.Position;
            int ofs = reader.ReadInt16();
            if (ofs == 0)
            {
                return -1;
            }
            return (int)(curr_ofs + ofs);
        }

        public virtual int GetSize()
        {
            switch (Format)
            {
                case NdrFormatCharacter.FC_BYTE:
                case NdrFormatCharacter.FC_SMALL:
                case NdrFormatCharacter.FC_CHAR:
                case NdrFormatCharacter.FC_USMALL:
                    return 1;
                case NdrFormatCharacter.FC_WCHAR:
                case NdrFormatCharacter.FC_SHORT:
                case NdrFormatCharacter.FC_USHORT:
                    return 2;
                case NdrFormatCharacter.FC_LONG:
                case NdrFormatCharacter.FC_ULONG:
                case NdrFormatCharacter.FC_FLOAT:
                // ENUM16 is still emitted as a 32 bit value.
                case NdrFormatCharacter.FC_ENUM16:
                case NdrFormatCharacter.FC_ENUM32:
                case NdrFormatCharacter.FC_ERROR_STATUS_T:
                    return 4;
                case NdrFormatCharacter.FC_HYPER:
                case NdrFormatCharacter.FC_DOUBLE:
                    return 8;
                case NdrFormatCharacter.FC_INT3264:
                case NdrFormatCharacter.FC_UINT3264:
                    return IntPtr.Size;
                default:
                    return 0;
            }
        }

        internal static NdrBaseTypeReference Read(NdrParseContext context, BinaryReader reader)
        {
            NdrFormatCharacter format = (NdrFormatCharacter)reader.ReadByte();

            // Loop to consume padding values.
            while (true)
            {
                switch (format)
                {
                    case NdrFormatCharacter.FC_BYTE:
                    case NdrFormatCharacter.FC_CHAR:
                    case NdrFormatCharacter.FC_SMALL:
                    case NdrFormatCharacter.FC_USMALL:
                    case NdrFormatCharacter.FC_WCHAR:
                    case NdrFormatCharacter.FC_SHORT:
                    case NdrFormatCharacter.FC_USHORT:
                    case NdrFormatCharacter.FC_LONG:
                    case NdrFormatCharacter.FC_ULONG:
                    case NdrFormatCharacter.FC_FLOAT:
                    case NdrFormatCharacter.FC_HYPER:
                    case NdrFormatCharacter.FC_DOUBLE:
                    case NdrFormatCharacter.FC_ENUM16:
                    case NdrFormatCharacter.FC_ENUM32:
                    case NdrFormatCharacter.FC_ERROR_STATUS_T:
                    case NdrFormatCharacter.FC_INT3264:
                    case NdrFormatCharacter.FC_UINT3264:
                        return new NdrSimpleTypeReference(format);
                    case NdrFormatCharacter.FC_END:
                        return null;
                    case NdrFormatCharacter.FC_OP:
                    case NdrFormatCharacter.FC_UP:
                    case NdrFormatCharacter.FC_RP:
                    case NdrFormatCharacter.FC_FP:
                        return new NdrPointerTypeReference(context, format, reader);
                    case NdrFormatCharacter.FC_IP:
                        return new NdrInterfacePointerTypeReference(context, reader);
                    case NdrFormatCharacter.FC_C_CSTRING:
                    case NdrFormatCharacter.FC_C_BSTRING:
                    case NdrFormatCharacter.FC_C_WSTRING:
                        return new NdrConformantStringTypeReference(context, format, reader);
                    case NdrFormatCharacter.FC_CSTRING:
                    case NdrFormatCharacter.FC_BSTRING:
                    case NdrFormatCharacter.FC_WSTRING:
                        return new NdrStringTypeReference(format, reader);
                    case NdrFormatCharacter.FC_C_SSTRING:
                    case NdrFormatCharacter.FC_SSTRING:
                        return new NdrStructureStringTypeReferece(format, reader);
                    case NdrFormatCharacter.FC_USER_MARSHAL:
                        return FixupUserMarshal(context, new NdrUserMarshalTypeReference(context, reader));
                    case NdrFormatCharacter.FC_EMBEDDED_COMPLEX:
                        reader.ReadByte(); // Padding
                        return Read(context, ReadTypeOffset(reader));
                    case NdrFormatCharacter.FC_STRUCT:
                        return FixupSimpleStructureType(new NdrSimpleStructureTypeReference(context, reader));
                    case NdrFormatCharacter.FC_PSTRUCT:
                        return new NdrSimpleStructureWithPointersTypeReference(context, reader);
                    case NdrFormatCharacter.FC_CSTRUCT:
                        return new NdrConformantStructureTypeReference(context, reader);
                    case NdrFormatCharacter.FC_BOGUS_STRUCT:
                        return new NdrBogusStructureTypeReference(context, format, reader);
                    case NdrFormatCharacter.FC_FORCED_BOGUS_STRUCT:
                        return new NdrBogusStructureTypeReference(context, format, reader);
                    case NdrFormatCharacter.FC_PP:
                        return new NdrPointerInfoTypeReference(context, reader);
                    case NdrFormatCharacter.FC_SMFARRAY:
                    case NdrFormatCharacter.FC_LGFARRAY:
                        return new NdrSimpleArrayTypeReference(context, format, reader);
                    case NdrFormatCharacter.FC_CARRAY:
                    case NdrFormatCharacter.FC_CVARRAY:
                        return new NdrConformantArrayTypeReference(format, context, reader);
                    case NdrFormatCharacter.FC_BOGUS_ARRAY:
                        return new NdrBogusArrayTypeReference(context, reader);
                    case NdrFormatCharacter.FC_SMVARRAY:
                    case NdrFormatCharacter.FC_LGVARRAY:
                        return new NdrVaryingArrayTypeReference(context, format, reader);
                    case NdrFormatCharacter.FC_RANGE:
                        return new NdrRangeTypeReference(reader);
                    case NdrFormatCharacter.FC_ENCAPSULATED_UNION:
                    case NdrFormatCharacter.FC_NON_ENCAPSULATED_UNION:
                        return new NdrUnionTypeReference(format, context, reader);
                    // Skipping padding types.
                    case NdrFormatCharacter.FC_PAD:
                        break;
                    case NdrFormatCharacter.FC_STRUCTPAD1:
                    case NdrFormatCharacter.FC_STRUCTPAD2:
                    case NdrFormatCharacter.FC_STRUCTPAD3:
                    case NdrFormatCharacter.FC_STRUCTPAD4:
                    case NdrFormatCharacter.FC_STRUCTPAD5:
                    case NdrFormatCharacter.FC_STRUCTPAD6:
                    case NdrFormatCharacter.FC_STRUCTPAD7:
                        return new NdrStructurePaddingTypeReference(format);
                    case NdrFormatCharacter.FC_SYSTEM_HANDLE:
                        return new NdrSystemHandleTypeReference(reader);
                    case NdrFormatCharacter.FC_AUTO_HANDLE:
                    case NdrFormatCharacter.FC_CALLBACK_HANDLE:
                    case NdrFormatCharacter.FC_BIND_CONTEXT:
                    case NdrFormatCharacter.FC_BIND_PRIMITIVE:
                    case NdrFormatCharacter.FC_BIND_GENERIC:
                        return new NdrHandleTypeReference(format);
                    case NdrFormatCharacter.FC_PIPE:
                        return new NdrPipeTypeReference(context, reader);
                    case NdrFormatCharacter.FC_SUPPLEMENT:
                        return new NdrSupplementTypeReference(context, reader);
                    default:
                        return new NdrUnknownTypeReference(format);
                }

                format = (NdrFormatCharacter)reader.ReadByte();
            }
        }

        internal static BinaryReader GetReader(NdrParseContext context, int ofs)
        {
            BinaryReader reader = context.Reader.GetReader(context.TypeDesc);
            reader.BaseStream.Position = ofs;
            return reader;
        }

        internal static NdrBaseTypeReference Read(NdrParseContext context, int ofs)
        {
            if (ofs < 0)
            {
                return null;
            }

            IntPtr type_ofs = context.TypeDesc + ofs;
            if (context.TypeCache.Cache.ContainsKey(type_ofs))
            {
                return context.TypeCache.Cache[type_ofs];
            }

            // Add a pending refence type, this is used only if the current type refers to itself (or indirectly).
            NdrIndirectTypeReference ref_type = new NdrIndirectTypeReference();
            context.TypeCache.Cache.Add(type_ofs, ref_type);

            NdrBaseTypeReference ret = Read(context, GetReader(context, ofs));
            ref_type.FixupType(ret);
            // Replace type cache entry with real value.
            context.TypeCache.Cache[type_ofs] = ret;
            return ret;
        }
    }

    [Serializable]
    public sealed class NdrSimpleTypeReference : NdrBaseTypeReference
    {
        internal NdrSimpleTypeReference(NdrFormatCharacter format)
            : base(format)
        {
        }
    }

#pragma warning restore 1591
}
