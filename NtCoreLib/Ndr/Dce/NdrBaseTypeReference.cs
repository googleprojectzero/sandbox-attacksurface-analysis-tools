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

using NtCoreLib.Ndr.Formatter;
using NtCoreLib.Ndr.Parser;
using NtCoreLib.Win32.Loader;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NtCoreLib.Ndr.Dce;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
[Serializable]
public abstract class NdrBaseTypeReference
{
    public NdrFormatCharacter Format { get; }

    protected NdrBaseTypeReference(NdrFormatCharacter format)
    {
        Format = format;
    }

    public override string ToString() => $"{Format} - {GetType().Name}";

    internal virtual NdrCorrelationDescriptor GetConformanceDescriptor()
    {
        return null;
    }

    internal virtual NdrCorrelationDescriptor GetVarianceDescriptor()
    {
        return null;
    }

    private protected virtual string FormatType(INdrFormatterContext context)
    {
        return context.SimpleTypeToName(Format);
    }

    internal string FormatTypeInternal(INdrFormatterContext context)
    {
        return FormatType(context);
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

        private readonly IntPtr _size_ptr;
        private readonly IntPtr _size_64_ptr;
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
                using var lib = SafeLoadLibraryHandle.LoadLibrary("combase.dll");
                LoadMarshallersForComBase(lib);
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
            // REX prefix, could be a lea rax, ofs import - Delay load 64bit or a jmp.
            case 0x48:
                {
                    if (!Environment.Is64BitProcess)
                    {
                        return ptr;
                    }
                    start_byte = System.Runtime.InteropServices.Marshal.ReadByte(ptr + 1);
                    if (start_byte == 0xFF)
                    {
                        return GetTargetAddress(curr_module, ptr + 1);
                    }
                    if (start_byte != 0x8D || System.Runtime.InteropServices.Marshal.ReadByte(ptr + 2) != 0x05)
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

        using (var lib = SafeLoadLibraryHandle.GetModuleHandle(ptr, false))
        {
            if (!lib.IsSuccess || lib.Result.DangerousGetHandle() != curr_module.DangerousGetHandle())
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
                + type.QuadrupleIndex * context.Reader.PointerSize * 4);

        // If in process try and read out known type by walking pointers.
        if (context.Reader.InProcess && !context.HasFlag(NdrParserFlags.IgnoreUserMarshal))
        {
            using var module = SafeLoadLibraryHandle.GetModuleHandle(context.StubDesc.aUserMarshalQuadruple, false);

            if (!module.IsSuccess)
            {
                return type;
            }

            m_marshalers ??= new StandardUserMarshalers();

            NdrKnownTypes known_type = m_marshalers.GetKnownType(marshal_ptr);
            if (known_type == NdrKnownTypes.None)
            {
                IntPtr usersize_ptr = GetTargetAddress(module.Result, marshal_ptr);
                known_type = m_marshalers.GetKnownType(usersize_ptr);
            }

            if (known_type != NdrKnownTypes.None)
            {
                return new NdrKnownTypeReference(known_type);
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
                if (name.Equals("LOCAL_HSTRING"))
                    return new NdrKnownTypeReference(NdrKnownTypes.HSTRING);
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
                if (members[3] is NdrSimpleArrayTypeReference array && array.TotalSize == 8 
                    && array.ElementType.Format == NdrFormatCharacter.FC_BYTE)
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
        return Format switch
        {
            NdrFormatCharacter.FC_BYTE or NdrFormatCharacter.FC_SMALL or NdrFormatCharacter.FC_CHAR or NdrFormatCharacter.FC_USMALL => 1,
            NdrFormatCharacter.FC_WCHAR or NdrFormatCharacter.FC_SHORT or NdrFormatCharacter.FC_USHORT => 2,
            NdrFormatCharacter.FC_LONG or NdrFormatCharacter.FC_ULONG or NdrFormatCharacter.FC_FLOAT or NdrFormatCharacter.FC_ENUM16 or NdrFormatCharacter.FC_ENUM32 or NdrFormatCharacter.FC_ERROR_STATUS_T => 4,
            NdrFormatCharacter.FC_HYPER or NdrFormatCharacter.FC_DOUBLE => 8,
            NdrFormatCharacter.FC_INT3264 or NdrFormatCharacter.FC_UINT3264 => IntPtr.Size,
            _ => 0,
        };
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
                case NdrFormatCharacter.FC_CPSTRUCT:
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
                case NdrFormatCharacter.FC_ALIGNM2:
                case NdrFormatCharacter.FC_ALIGNM4:
                case NdrFormatCharacter.FC_ALIGNM8:
                    return new NdrStructureAlignTypeReference(format);
                case NdrFormatCharacter.FC_IGNORE:
                    return new NdrIgnoreTypeReference();
                case NdrFormatCharacter.FC_SYSTEM_HANDLE:
                    return new NdrSystemHandleTypeReference(reader);
                case NdrFormatCharacter.FC_AUTO_HANDLE:
                case NdrFormatCharacter.FC_CALLBACK_HANDLE:
                case NdrFormatCharacter.FC_BIND_PRIMITIVE:
                case NdrFormatCharacter.FC_BIND_GENERIC:
                    return new NdrHandleTypeReference(format);
                case NdrFormatCharacter.FC_BIND_CONTEXT:
                    return new NdrContextHandleTypeReference(reader);
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
        Stream stm = context.Reader.GetStream(context.TypeDesc);
        stm.Position = ofs;
        return new(stm);
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

        // Add a pending reference type, this is used only if the current type refers to itself (or indirectly).
        NdrIndirectTypeReference ref_type = new();
        context.TypeCache.Cache.Add(type_ofs, ref_type);

        NdrBaseTypeReference ret = Read(context, GetReader(context, ofs));
        ref_type.FixupType(ret);
        // Replace type cache entry with real value.
        context.TypeCache.Cache[type_ofs] = ret;
        return ret;
    }
}

#pragma warning restore 1591

