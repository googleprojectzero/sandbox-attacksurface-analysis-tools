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

using NtCoreLib.Ndr.Parser;
using System;
using System.IO;

namespace NtCoreLib.Ndr.Dce;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
[Serializable]
public sealed class NdrVaryingArrayTypeReference : NdrBaseArrayTypeReference
{
    private readonly int _element_size;

    public int TotalSize { get; }
    public int NumberofElements { get; }
    public NdrCorrelationDescriptor VarianceDescriptor { get; }

    internal override NdrCorrelationDescriptor GetVarianceDescriptor()
    {
        return VarianceDescriptor;
    }

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
}
#pragma warning restore 1591

