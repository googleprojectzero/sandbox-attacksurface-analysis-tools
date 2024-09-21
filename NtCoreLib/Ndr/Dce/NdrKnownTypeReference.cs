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

using NtCoreLib.Ndr.Formatter;
using System;

namespace NtCoreLib.Ndr.Dce;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
[Serializable]
public sealed class NdrKnownTypeReference : NdrBaseTypeReference
{
    public NdrKnownTypes KnownType { get; }

    public NdrKnownTypeReference(NdrKnownTypes type)
        : base(NdrFormatCharacter.FC_USER_MARSHAL)
    {
        KnownType = type;
    }

    private protected override string FormatType(INdrFormatterContext context)
    {
        return KnownType.ToString();
    }

    public override int GetSize()
    {
        return KnownType switch
        {
            NdrKnownTypes.GUID => 16,
            NdrKnownTypes.BSTR or NdrKnownTypes.LPSAFEARRAY or NdrKnownTypes.HWND or NdrKnownTypes.HENHMETAFILE or NdrKnownTypes.HMETAFILEPICT or NdrKnownTypes.HMETAFILE or NdrKnownTypes.HACCEL or NdrKnownTypes.HBITMAP or NdrKnownTypes.HBRUSH or NdrKnownTypes.HDC or NdrKnownTypes.HGLOBAL or NdrKnownTypes.HICON or NdrKnownTypes.HMENU or NdrKnownTypes.HMONITOR or NdrKnownTypes.HPALETTE or NdrKnownTypes.HRGN or NdrKnownTypes.HSTRING or NdrKnownTypes.WdtpInterfacePointer => IntPtr.Size,
            NdrKnownTypes.VARIANT => Environment.Is64BitProcess ? 24 : 16,
            NdrKnownTypes.SNB or NdrKnownTypes.CLIPFORMAT => 4,
            NdrKnownTypes.STGMEDIUM => Environment.Is64BitProcess ? 24 : 12,
            _ => throw new ArgumentException("Unknown Known Type"),
        };
    }
}

#pragma warning restore 1591

