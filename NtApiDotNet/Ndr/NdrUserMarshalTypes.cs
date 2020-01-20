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
    public enum NdrUserMarshalFlags : byte
    {
        USER_MARSHAL_POINTER = 0xc0,
        USER_MARSHAL_UNIQUE = 0x80,
        USER_MARSHAL_REF = 0x40,
        USER_MARSHAL_IID = 0x20
    }

    [Serializable]
    public sealed class NdrUserMarshalTypeReference : NdrBaseTypeReference
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

        internal override string FormatType(INdrFormatterInternal formatter)
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
    public sealed class NdrNamedTypeReference : NdrBaseTypeReference
    {
        public string Name { get; }

        public NdrNamedTypeReference(string name)
            : base(NdrFormatCharacter.FC_USER_MARSHAL)
        {
            Name = name;
        }

        internal override string FormatType(INdrFormatterInternal formatter)
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
    public sealed class NdrKnownTypeReference : NdrBaseTypeReference
    {
        public NdrKnownTypes KnownType { get; }

        public NdrKnownTypeReference(NdrKnownTypes type)
            : base(NdrFormatCharacter.FC_USER_MARSHAL)
        {
            KnownType = type;
        }

        internal override string FormatType(INdrFormatterInternal formatter)
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

#pragma warning restore 1591
}
