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

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
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
        if (SupplementType is NdrContextHandleTypeReference context_handle)
        {
            context_handle.IsStrict = true;
        }
    
        Argument1 = reader.ReadInt32();
        Argument2 = reader.ReadInt32();
    }

    private protected override string FormatType(INdrFormatterContext context)
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

        return $"{context.FormatComment(comment)}{context.FormatType(SupplementType)}";
    }

    public override int GetSize()
    {
        return IntPtr.Size;
    }
}
#pragma warning restore 1591

