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
using NtCoreLib.Ndr.Parser;

namespace NtCoreLib.Ndr.Dce;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
[Serializable]
public sealed class NdrBogusArrayTypeReference : NdrBaseArrayTypeReference
{
    public int NumberofElements { get; }
    public NdrCorrelationDescriptor ConformanceDescriptor { get; }
    public NdrCorrelationDescriptor VarianceDescriptor { get; }

    internal NdrBogusArrayTypeReference(NdrParseContext context, BinaryReader reader)
        : base(context, NdrFormatCharacter.FC_BOGUS_ARRAY, reader)
    {
        NumberofElements = reader.ReadInt16();
        ConformanceDescriptor = new NdrCorrelationDescriptor(context, reader);
        VarianceDescriptor = new NdrCorrelationDescriptor(context, reader);
        ReadElementType(context, reader);
    }

    internal override NdrCorrelationDescriptor GetConformanceDescriptor()
    {
        return ConformanceDescriptor;
    }

    internal override NdrCorrelationDescriptor GetVarianceDescriptor()
    {
        return VarianceDescriptor;
    }

    protected override int GetElementCount()
    {
        if (NumberofElements > 0)
        {
            return NumberofElements;
        }

        if (VarianceDescriptor.IsConstant)
        {
            return VarianceDescriptor.Offset;
        }

        if (ConformanceDescriptor.IsConstant)
        {
            return ConformanceDescriptor.Offset;
        }

        return 0;
    }
}
#pragma warning restore 1591

