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
using NtCoreLib.Ndr.Parser;
using System;
using System.IO;

namespace NtCoreLib.Ndr.Dce;

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

    private protected override sealed string FormatType(INdrFormatterContext context)
    {
        return context.FormatArrayType(this);
    }

    protected override void OnFixupLateBoundTypes()
    {
        ElementType = GetIndirectType(ElementType);
    }
}
#pragma warning restore 1591

