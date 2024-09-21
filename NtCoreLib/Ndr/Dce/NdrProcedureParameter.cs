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

using NtCoreLib.Ndr.Parser;
using System;
using System.IO;

namespace NtCoreLib.Ndr.Dce;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
[Serializable]
public class NdrProcedureParameter
{
    public NdrParamAttributes Attributes { get; }
    public NdrBaseTypeReference Type { get; }
    public int ServerAllocSize { get; }
    public int Offset { get; }
    public string Name { get; set; }
    public bool IsIn => Attributes.HasFlag(NdrParamAttributes.IsIn);
    public bool IsOut => Attributes.HasFlag(NdrParamAttributes.IsOut);
    public bool IsInOut => IsIn && IsOut;
    public bool IsSimpleRef => Attributes.HasFlag(NdrParamAttributes.IsSimpleRef);
    public bool IsPipe => Attributes.HasFlag(NdrParamAttributes.IsPipe);

    private const ushort ServerAllocSizeMask = 0xe000;

    internal NdrProcedureParameter(NdrParamAttributes attributes, int server_alloc_size, NdrBaseTypeReference type, int offset, string name)
    {
        Attributes = attributes;
        ServerAllocSize = server_alloc_size;
        Type = type;
        Offset = offset;
        Name = name;
    }

    internal NdrProcedureParameter(NdrParseContext context, BinaryReader reader, string name)
    {
        ushort attr = reader.ReadUInt16();
        Attributes = (NdrParamAttributes)(attr & ~ServerAllocSizeMask);
        ServerAllocSize = (attr & ServerAllocSizeMask) >> 10;
        Offset = reader.ReadUInt16();
        Name = name;
        if ((Attributes & NdrParamAttributes.IsBasetype) == 0)
        {
            int type_ofs = reader.ReadUInt16();
            Type = NdrBaseTypeReference.Read(context, type_ofs);
        }
        else
        {
            Type = new NdrSimpleTypeReference((NdrFormatCharacter)reader.ReadByte());
            // Remove padding.
            reader.ReadByte();
        }
    }

    public override string ToString() => $"{Type} - {Attributes}";
}

#pragma warning restore 1591
