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
using NtCoreLib.Ndr.Formatter;
using NtCoreLib.Ndr.Parser;

namespace NtCoreLib.Ndr.Dce;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
[Serializable]
public sealed class NdrConformantStringTypeReference : NdrBaseStringTypeReference
{
    public NdrCorrelationDescriptor ConformanceDescriptor { get; }

    internal override NdrCorrelationDescriptor GetConformanceDescriptor()
    {
        return ConformanceDescriptor;
    }

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

    private protected override string FormatType(INdrFormatterContext context)
    {
        string conformance_desc = string.Empty;
        if (ConformanceDescriptor != null && ConformanceDescriptor.IsValid)
        {
            conformance_desc = context.FormatComment(ConformanceDescriptor.ToString());
        }

        return $"{conformance_desc}{base.FormatType(context)}";
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

#pragma warning restore 1591

