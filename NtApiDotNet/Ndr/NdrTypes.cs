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
        FC_HARD_STRUCT = 0xb1,      // 0xb1
        FC_TRANSMIT_AS_PTR,         // 0xb2
        FC_REPRESENT_AS_PTR,        // 0xb3
        FC_USER_MARSHAL,            // 0xb4
        FC_PIPE,                    // 0xb5
        FC_BLKHOLE,                 // 0xb6
        FC_RANGE,                   // 0xb7     
        FC_INT3264,                 // 0xb8     
        FC_UINT3264,                // 0xb9    
        FC_END_OF_UNIVERSE          // 0xba
    }

    [Flags]
    public enum NdrPointerFlags : byte
    {
        FC_ALLOCATE_ALL_NODES = 0x01,
        FC_DONT_FREE = 0x02,
        FC_ALLOCED_ON_STACK = 0x04,
        FC_SIMPLE_POINTER = 0x08,
        FC_POINTER_DEREF = 0x10,
    }

    [Flags]
    public enum NdrUserMarshalFlags : byte
    {
        USER_MARSHAL_POINTER = 0xc0,
        USER_MARSHAL_UNIQUE = 0x80,
        USER_MARSHAL_REF = 0x40,
        USER_MARSHAL_IID = 0x20
    }

    public class NdrInterfacePointerTypeReference : NdrBaseTypeReference
    {
        internal static readonly Guid IID_IUnknown = new Guid("{00000000-0000-0000-C000-000000000046}");

        public Guid Iid { get; private set; }

        public bool IsConstant { get; private set; }

        public NdrCorrelationDescriptor IidIsDescriptor { get; private set; }

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
                Iid = IID_IUnknown;
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

    public class NdrPointerTypeReference : NdrBaseTypeReference
    {
        public NdrBaseTypeReference Type { get; private set; }
        public NdrPointerFlags Flags { get; private set; }

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
                Type = new NdrBaseTypeReference(ReadFormat(reader));
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

                return String.Format("{0}{1}*", is_unique ? "/* unique */ " : "", Type.FormatType(formatter));
            }
        }

        public override int GetSize()
        {
            return IntPtr.Size;
        }
    }

    public class NdrStringTypeReference : NdrBaseTypeReference
    {
        public int StringSize { get; private set; }

        internal NdrStringTypeReference(NdrFormatCharacter format, BinaryReader reader) : base(format)
        {
            switch (format)
            {
                case NdrFormatCharacter.FC_BSTRING:
                case NdrFormatCharacter.FC_CSTRING:
                case NdrFormatCharacter.FC_WSTRING:
                    StringSize = reader.ReadUInt16();
                    break;
            }
        }

        internal override string FormatType(NdrFormatter context)
        {
            if (StringSize > 0)
            {
                return String.Format("{0}[{1}]", base.FormatType(context), StringSize);
            }
            else
            {
                return base.FormatType(context);
            }
        }

        public override int GetSize()
        {
            return StringSize;
        }
    }

    public class NdrStructureStringTypeReferece : NdrBaseTypeReference
    {
        public int ElementSize { get; private set; }
        public int NumberOfElements { get; private set; }
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
            return String.Format("{0}<{1}>[{2}]", base.FormatType(formatter), ElementSize, NumberOfElements);
        }
    }

    public class NdrUserMarshalTypeReference : NdrBaseTypeReference
    {
        public NdrUserMarshalFlags Flags { get; private set; }
        public int QuadrupleIndex { get; private set; }
        public int UserTypeMemorySite { get; private set; }
        public int TransmittedTypeBufferSize { get; private set; }
        public NdrBaseTypeReference Type { get; private set; }

        internal NdrUserMarshalTypeReference(NdrParseContext context, BinaryReader reader)
            : base(NdrFormatCharacter.FC_USER_MARSHAL)
        {
            Flags = (NdrUserMarshalFlags)(reader.ReadByte() & 0xF0);
            QuadrupleIndex = reader.ReadUInt16();
            UserTypeMemorySite = reader.ReadUInt16();
            TransmittedTypeBufferSize = reader.ReadUInt16();
            Type = NdrBaseTypeReference.Read(context, ReadTypeOffset(reader));
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

    public class NdrKnownTypeReference : NdrBaseTypeReference
    {
        public NdrKnownTypes KnownType { get; private set; }

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

    public class NdrStructureMember
    {
        public NdrBaseTypeReference MemberType { get; private set; }
        public int Offset { get; private set; }

        internal NdrStructureMember(NdrBaseTypeReference member_type, int offset)
        {
            MemberType = member_type;
            Offset = offset;
        }

        internal string FormatMember(NdrFormatter context)
        {
            return String.Format("/* Offset: {0} */ {1}", Offset, MemberType.FormatType(context));
        }
    }

    public class NdrBaseStructureTypeReference : NdrComplexTypeReference
    {
        protected List<NdrBaseTypeReference> _members;
        public int Alignment { get; private set; }
        public int MemorySize { get; private set; }

        private IEnumerable<NdrStructureMember> GetMembers()
        {
            int current_offset = 0;
            foreach (var type in _members)
            {
                if (!(type is NdrStructurePaddingTypeReference))
                {
                    yield return new NdrStructureMember(type, current_offset);
                }
                current_offset += type.GetSize();
            }
        }

        public IEnumerable<NdrBaseTypeReference> MembersTypes { get { return _members.AsReadOnly(); } }

        public IEnumerable<NdrStructureMember> Members { get { return GetMembers(); } }

        internal NdrBaseStructureTypeReference(NdrParseContext context, NdrFormatCharacter format, BinaryReader reader)
            : base($"Struct_{context.TypeCache.GetNextComplexId()}", format)
        {
            Alignment = reader.ReadByte();
            MemorySize = reader.ReadUInt16();
            _members = new List<NdrBaseTypeReference>();
        }

        internal void ReadMemberInfo(NdrParseContext context, BinaryReader reader)
        {
            NdrBaseTypeReference curr_type;
            while ((curr_type = Read(context, reader)) != null)
            {
                _members.Add(curr_type);
            }
        }

        internal override string FormatType(NdrFormatter context)
        {
            return $"struct {Name}";
        }

        internal override string FormatComplexType(NdrFormatter context)
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendFormat("/* Memory Size: {0} */", GetSize()).AppendLine();
            builder.Append(FormatType(context)).AppendLine(" {");
            foreach (var member in Members.Select((m, i) => $"{m.FormatMember(context)} Member{i}"))
            {
                builder.Append("    ").AppendLine(member);
            }
            builder.AppendLine("};");
            return builder.ToString();
        }

        public override int GetSize()
        {
            return MemorySize;
        }
    }

    public class NdrSimpleStructureTypeReference : NdrBaseStructureTypeReference
    {
        internal NdrSimpleStructureTypeReference(NdrParseContext context, BinaryReader reader)
            : base(context, NdrFormatCharacter.FC_STRUCT, reader)
        {
            ReadMemberInfo(context, reader);
        }
    }

    public class NdrConformantStructureTypeReference : NdrBaseStructureTypeReference
    {
        internal NdrConformantStructureTypeReference(NdrParseContext context, BinaryReader reader)
            : base(context, NdrFormatCharacter.FC_CSTRUCT, reader)
        {
            NdrBaseTypeReference array = Read(context, ReadTypeOffset(reader));
            ReadMemberInfo(context, reader);
            if (array != null)
            {
                _members.Add(array);
            }
        }
    }

    public class NdrBogusStructureTypeReference : NdrBaseStructureTypeReference
    {
        internal NdrBogusStructureTypeReference(NdrParseContext context, BinaryReader reader)
            : base(context, NdrFormatCharacter.FC_BOGUS_STRUCT, reader)
        {
            NdrBaseTypeReference array = Read(context, ReadTypeOffset(reader));
            int pointer_ofs = ReadTypeOffset(reader);
            ReadMemberInfo(context, reader);
            if (pointer_ofs >= 0)
            {
                BinaryReader pointer_reader = GetReader(context, pointer_ofs);
                for (int i = 0; i < _members.Count; ++i)
                {
                    if (_members[i].Format == NdrFormatCharacter.FC_POINTER)
                    {
                        _members[i] = Read(context, reader);
                    }
                }
            }

            if (array != null)
            {
                _members.Add(array);
            }
        }
    }

    public class NdrHardStructureTypeReference : NdrBaseStructureTypeReference
    {
        public int EnumOffset { get; private set; }
        public int CopySize { get; private set; }
        public int MemCopyIncr { get; private set; }
        public int UnionDescOffset { get; private set; }

        internal NdrHardStructureTypeReference(NdrParseContext context, BinaryReader reader)
            : base(context, NdrFormatCharacter.FC_HARD_STRUCT, reader)
        {
            // Reserved.
            reader.ReadInt32();
            EnumOffset = reader.ReadInt16();
            //CopySize = reader.ReadInt16();
            //MemCopyIncr = reader.ReadInt16();
            UnionDescOffset = reader.ReadInt16();
            ReadMemberInfo(context, reader);
        }
    }

    public class NdrBaseArrayTypeReference : NdrBaseTypeReference
    {
        public int Alignment { get; private set; }
        public NdrBaseTypeReference ElementType { get; private set; }

        internal NdrBaseArrayTypeReference(NdrParseContext context, NdrFormatCharacter format, BinaryReader reader) : base(format)
        {
            Alignment = reader.ReadByte();
        }

        internal void ReadElementType(NdrParseContext context, BinaryReader reader)
        {
            ElementType = Read(context, reader);
        }

        protected virtual int GetArraySize()
        {
            return 0;
        }

        internal override string FormatType(NdrFormatter context)
        {
            int array_size = GetArraySize();
            return String.Format("{0}[{1}]", ElementType.FormatType(context), array_size == 0 ? String.Empty : array_size.ToString());
        }
    }

    public class NdrSimpleArrayTypeReference : NdrBaseArrayTypeReference
    {
        public int TotalSize { get; private set; }

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

        public override int GetSize()
        {
            return TotalSize;
        }

        protected override int GetArraySize()
        {
            return TotalSize;
        }
    }

    public class NdrConformantArrayTypeReference : NdrBaseArrayTypeReference
    {
        public int ElementSize { get; private set; }
        public NdrCorrelationDescriptor ConformanceDescriptor { get; private set; }
        public NdrCorrelationDescriptor VarianceDescriptor { get; private set; }

        internal NdrConformantArrayTypeReference(NdrFormatCharacter format, NdrParseContext context,
            BinaryReader reader) : base(context, format, reader)
        {
            ElementSize = reader.ReadInt16();
            ConformanceDescriptor = new NdrCorrelationDescriptor(context, reader);
            if (format == NdrFormatCharacter.FC_CVARRAY)
            {
                VarianceDescriptor = new NdrCorrelationDescriptor(context, reader);
            }
            ReadElementType(context, reader);
        }

        protected override int GetArraySize()
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

            return base.GetArraySize();
        }
    }

    public class NdrBogusArrayTypeReference : NdrBaseArrayTypeReference
    {
        public int NumberofElements { get; private set; }
        public NdrCorrelationDescriptor ConformanceDescriptor { get; private set; }
        public NdrCorrelationDescriptor VarianceDescriptor { get; private set; }

        internal NdrBogusArrayTypeReference(NdrParseContext context, BinaryReader reader)
            : base(context, NdrFormatCharacter.FC_BOGUS_ARRAY, reader)
        {
            NumberofElements = reader.ReadInt16();
            ConformanceDescriptor = new NdrCorrelationDescriptor(context, reader);
            VarianceDescriptor = new NdrCorrelationDescriptor(context, reader);
            ReadElementType(context, reader);
        }

        protected override int GetArraySize()
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

            if (ConformanceDescriptor != null
                && ConformanceDescriptor.CorrelationType == NdrCorrelationType.FC_CONSTANT_CONFORMANCE)
            {
                return ConformanceDescriptor.Offset;
            }

            return base.GetArraySize();
        }

        public override int GetSize()
        {
            return NumberofElements * ElementType.GetSize();
        }
    }

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

    public class NdrPointerInfoInstance
    {
        public int OffsetInMemory { get; private set; }
        public int OffsetInBuffer { get; private set; }
        public NdrPointerTypeReference PointerType { get; private set; }

        internal NdrPointerInfoInstance(NdrParseContext context, BinaryReader reader)
        {
            OffsetInMemory = reader.ReadInt16();
            OffsetInBuffer = reader.ReadInt16();
            PointerType = NdrBaseTypeReference.Read(context, reader) as NdrPointerTypeReference;
        }
    }

    public class NdrPointerInfoTypeReference : NdrBaseTypeReference
    {
        public NdrFormatCharacter BasePointerType { get; private set; }
        public NdrFormatCharacter SubPointerType { get; private set; }
        public int Iterations { get; private set; }
        public int Increment { get; private set; }
        public int OffsetToArray { get; private set; }
        public IEnumerable<NdrPointerInfoInstance> PointerInstances { get; private set; }

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

    public class NdrRangeTypeReference : NdrBaseTypeReference
    {
        public NdrBaseTypeReference RangeType { get; private set; }
        public int MinValue { get; private set; }
        public int MaxValue { get; private set; }

        public NdrRangeTypeReference(BinaryReader reader) : base(NdrFormatCharacter.FC_RANGE)
        {
            RangeType = new NdrBaseTypeReference((NdrFormatCharacter)reader.ReadByte());
            MinValue = reader.ReadInt32();
            MaxValue = reader.ReadInt32();
        }

        internal override string FormatType(NdrFormatter context)
        {
            return String.Format("/* range: {0},{1} */ {2}", MinValue, MaxValue, RangeType.FormatType(context));
        }

        public override int GetSize()
        {
            return RangeType.GetSize();
        }
    }

    public class NdrIndirectTypeReference : NdrBaseTypeReference
    {
        NdrBaseTypeReference _ref_type;

        internal void FixupType(NdrBaseTypeReference ref_type)
        {
            _ref_type = ref_type;
        }

        internal NdrIndirectTypeReference() : base(NdrFormatCharacter.FC_ZERO)
        {
        }

        internal override string FormatType(NdrFormatter context)
        {
            return _ref_type.FormatType(context);
        }

        public override int GetSize()
        {
            return _ref_type.GetSize();
        }

        public override string ToString()
        {
            return _ref_type.ToString();
        }
    }

    public sealed class NdrUnionArm
    {
        public NdrBaseTypeReference ArmType { get; private set; }
        public int CaseValue { get; private set; }

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
                return new NdrBaseTypeReference((NdrFormatCharacter)(type & 0xFF));
            }
            else if (type == 0)
            {
                return new NdrBaseTypeReference(NdrFormatCharacter.FC_ZERO);
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

    public sealed class NdrUnionArms
    {
        public int MemorySize { get; private set; }
        public IEnumerable<NdrUnionArm> Arms { get; private set; }
        public NdrBaseTypeReference DefaultArm { get; private set; }
        public int Alignment { get; private set; }

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

    public abstract class NdrComplexTypeReference : NdrBaseTypeReference
    {
        public string Name { get; }
        internal abstract string FormatComplexType(NdrFormatter context);

        internal NdrComplexTypeReference(string name, NdrFormatCharacter format) : base(format)
        {
            Name = name;
        }
    }

    public sealed class NdrUnionTypeReference : NdrComplexTypeReference
    {
        public NdrFormatCharacter SwitchType { get; private set; }
        public int SwitchIncrement { get; private set; }
        public NdrUnionArms Arms { get; private set; }
        public NdrCorrelationDescriptor Correlation { get; private set; }

        internal NdrUnionTypeReference(NdrFormatCharacter format, NdrParseContext context, BinaryReader reader)
            : base($"Union_{context.TypeCache.GetNextComplexId()}", format)
        {
            int switch_type = reader.ReadByte();
            SwitchIncrement = (switch_type >> 4) & 0xF;
            SwitchType = (NdrFormatCharacter)(switch_type & 0xF);

            if (format == NdrFormatCharacter.FC_NON_ENCAPSULATED_UNION)
            {
                Correlation = new NdrCorrelationDescriptor(context, reader);
                Arms = new NdrUnionArms(context, NdrBaseTypeReference.ReadTypeOffset(reader));
            }
            else
            {
                Arms = new NdrUnionArms(context, reader);
            }
        }

        internal override string FormatType(NdrFormatter context)
        {
            return String.Format("{0} {1}",
                 Format == NdrFormatCharacter.FC_NON_ENCAPSULATED_UNION ? "union" : "struct",
                 Name);
        }

        internal override string FormatComplexType(NdrFormatter context)
        {
            int indent = 4;
            StringBuilder builder = new StringBuilder();
            builder.AppendFormat("/* Memory Size: {0} */", GetSize()).AppendLine();
            builder.Append(FormatType(context)).AppendLine(" {");

            if (Format == NdrFormatCharacter.FC_ENCAPSULATED_UNION)
            {
                builder.Append(' ', indent).AppendFormat("{0} Selector;", new NdrBaseTypeReference(SwitchType).FormatType(context)).AppendLine();
                builder.Append(' ', indent).AppendLine("union { ");
                indent *= 2;
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
                    builder.Append(' ', indent).AppendFormat("{0} Default;", new NdrBaseTypeReference(Arms.DefaultArm.Format).FormatType(context)).AppendLine();
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

    public sealed class NdrSystemHandleTypeReference : NdrBaseTypeReference
    {
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
                    case NdrSystemHandleResource.File:
                        access = (FileAccessRights)AccessMask;
                        break;
                    case NdrSystemHandleResource.Process:
                        access = (ProcessAccessRights)AccessMask;
                        break;
                    case NdrSystemHandleResource.Thread:
                        access = (ThreadAccessRights)AccessMask;
                        break;
                    default:
                        access = string.Format("0x{0:X}", AccessMask);
                        break;
                }

                return string.Format("/* FC_SYSTEM_HANDLE {0}({1}) */ HANDLE", Resource, access);
            }
            return string.Format("/* FC_SYSTEM_HANDLE {0} */ HANDLE", Resource);
        }

        public override int GetSize()
        {
            return IntPtr.Size;
        }
    }

    public class NdrBaseTypeReference
    {
        public NdrFormatCharacter Format { get; private set; }

        protected internal NdrBaseTypeReference(NdrFormatCharacter format)
        {
            Format = format;
        }

        public override string ToString()
        {
            return String.Format("{0} - {1}", Format, GetType().Name);
        }

        internal virtual string FormatType(NdrFormatter context)
        {
            return context.SimpleTypeToName(Format);
        }

        internal static NdrFormatCharacter ReadFormat(BinaryReader reader)
        {
            return (NdrFormatCharacter)reader.ReadByte();
        }

        private class StandardUserMarshaler
        {
            public NdrKnownTypes KnownType { get; private set; }
            public bool IsMatch(IntPtr ptr)
            {
                return ptr == _size_ptr || ptr == _size_64_ptr;
            }

            public StandardUserMarshaler(SafeLoadLibraryHandle lib, NdrKnownTypes known_type)
            {
                _size_ptr = lib.GetProcAddress(String.Format("{0}_UserSize", known_type));
                _size_64_ptr = lib.GetProcAddress(String.Format("{0}_UserSize64", known_type));
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
            if (context.StubDesc.aUserMarshalQuadruple == IntPtr.Zero || !context.Reader.InProcess)
            {
                return type;
            }

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

                IntPtr usersize_ptr = GetTargetAddress(module,
                    Marshal.ReadIntPtr(context.StubDesc.aUserMarshalQuadruple, type.QuadrupleIndex * IntPtr.Size * 4));

                NdrKnownTypes known_type = m_marshalers.GetKnownType(usersize_ptr);
                if (known_type != NdrKnownTypes.None)
                {
                    return new NdrKnownTypeReference(known_type);
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
                    return 1;
                case NdrFormatCharacter.FC_USMALL:
                case NdrFormatCharacter.FC_WCHAR:
                case NdrFormatCharacter.FC_SHORT:
                case NdrFormatCharacter.FC_USHORT:
                case NdrFormatCharacter.FC_ENUM16:
                    return 2;
                case NdrFormatCharacter.FC_LONG:
                case NdrFormatCharacter.FC_ULONG:
                case NdrFormatCharacter.FC_FLOAT:
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
                        return new NdrBaseTypeReference(format);
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
                    case NdrFormatCharacter.FC_CSTRUCT:
                        return new NdrConformantStructureTypeReference(context, reader);
                    case NdrFormatCharacter.FC_BOGUS_STRUCT:
                        return new NdrBogusStructureTypeReference(context, reader);
                    //case NdrFormatCharacter.FC_HARD_STRUCT:
                    //    return new NdrHardStructureTypeReference(context, reader);
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

#pragma warning restore 1591
}
