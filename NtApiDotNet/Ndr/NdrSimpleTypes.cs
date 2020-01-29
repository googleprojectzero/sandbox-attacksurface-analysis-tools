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
        FC_EXPR,                    // 0x5d
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
        FC_SUPPLEMENT,              // 0xb6 - Seemed to originally be FC_BLKHOLE.
        FC_RANGE,                   // 0xb7
        FC_INT3264,                 // 0xb8
        FC_UINT3264,                // 0xb9
        FC_CSARRAY,
        FC_CS_TAG,
        FC_STRUCTPADN,
        FC_INT128,
        FC_UINT128,
        FC_FLOAT80,
        FC_FLOAT128,
        FC_BUFFER_ALIGN,
        FC_ENCAP_UNION,
        FC_FIX_ARRAY,
        FC_CONF_ARRAY,
        FC_VAR_ARRAY,
        FC_CONFVAR_ARRAY,
        FC_FIX_FORCED_BOGUS_ARRAY,
        FC_FIX_BOGUS_ARRAY,
        FC_FORCED_BOGUS_ARRAY,
        FC_CHAR_STRING,
        FC_WCHAR_STRING,
        FC_STRUCT_STRING,
        FC_CONF_CHAR_STRING,
        FC_CONF_WCHAR_STRING,
        FC_CONF_STRUCT_STRING,
        FC_CONF_STRUCT,
        FC_CONF_PSTRUCT,
        FC_CONFVAR_STRUCT,
        FC_CONFVAR_PSTRUCT,
        FC_FORCED_BOGUS_STRUCT_2,
        FC_CONF_BOGUS_STRUCT,
        FC_FORCED_CONF_BOGUS_STRUCT,
        FC_END_OF_UNIVERSE
    }


    [Serializable]
    public abstract class NdrBaseTypeReference
    {
        public NdrFormatCharacter Format { get; }

        protected NdrBaseTypeReference(NdrFormatCharacter format)
        {
            Format = format;
        }

        public override string ToString() => $"{Format} - {GetType().Name}";

        internal virtual string FormatType(INdrFormatterInternal context)
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
                _size_ptr = lib.GetProcAddress($"{known_type}_UserSize");
                _size_64_ptr = lib.GetProcAddress($"{known_type}_UserSize64");
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
            byte start_byte = System.Runtime.InteropServices.Marshal.ReadByte(ptr);
            switch (start_byte)
            {
                // Absolute jump.
                case 0xFF:
                    if (System.Runtime.InteropServices.Marshal.ReadByte(ptr + 1) != 0x25)
                    {
                        return ptr;
                    }

                    if (Environment.Is64BitProcess)
                    {
                        // RIP relative
                        ptr = System.Runtime.InteropServices.Marshal.ReadIntPtr(ptr + 6 + System.Runtime.InteropServices.Marshal.ReadInt32(ptr + 2));
                    }
                    else
                    {
                        // Absolute
                        ptr = System.Runtime.InteropServices.Marshal.ReadIntPtr(new IntPtr(System.Runtime.InteropServices.Marshal.ReadInt32(ptr + 2)));
                    }
                    break;
                // Relative jump.
                case 0xE9:
                    ptr = ptr + 5 + System.Runtime.InteropServices.Marshal.ReadInt32(ptr + 1);
                    break;
                // lea rax, ofs import - Delay load 64bit
                case 0x48:
                    {
                        if (!Environment.Is64BitProcess || System.Runtime.InteropServices.Marshal.ReadByte(ptr + 1) != 0x8D || System.Runtime.InteropServices.Marshal.ReadByte(ptr + 2) != 0x05)
                        {
                            return ptr;
                        }
                        IntPtr iat = ptr + System.Runtime.InteropServices.Marshal.ReadInt32(ptr + 3) + 7;
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
                        IntPtr iat = System.Runtime.InteropServices.Marshal.ReadIntPtr(ptr + 1);
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
                        return new NdrConformantStructureStringTypeReference(context, reader);
                    case NdrFormatCharacter.FC_SSTRING:
                        return new NdrStructureStringTypeReference(reader);
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
                    case NdrFormatCharacter.FC_CVSTRUCT:
                        return new NdrConformantStructureTypeReference(format, context, reader);
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
                    case NdrFormatCharacter.FC_IGNORE:
                        return new NdrIgnoreTypeReference();
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
                    case NdrFormatCharacter.FC_BYTE_COUNT_POINTER:
                        return new NdrByteCountPointerReferenceType(context, reader);
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
