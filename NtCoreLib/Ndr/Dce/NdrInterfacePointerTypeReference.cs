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
using NtCoreLib.Ndr.Interop;
using NtCoreLib.Ndr.Parser;

namespace NtCoreLib.Ndr.Dce;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
[Serializable]
public class NdrInterfacePointerTypeReference : NdrBaseTypeReference
{
    public Guid Iid { get; }

    public bool IsConstant { get; }

    public NdrCorrelationDescriptor IidIsDescriptor { get; }

    internal NdrInterfacePointerTypeReference(NdrParseContext context, BinaryReader reader) : base(NdrFormatCharacter.FC_IP)
    {
        NdrFormatCharacter type = ReadFormat(reader);
        if (type == NdrFormatCharacter.FC_CONSTANT_IID)
        {
            Iid = new Guid(reader.ReadAll(16));
            IsConstant = true;
        }
        else
        {
            Iid = NdrNativeUtils.IID_IUnknown;
            IidIsDescriptor = new NdrCorrelationDescriptor(context, reader);
        }
    }

    private protected override string FormatType(INdrFormatterContext context)
    {
        if (IsConstant)
        {
            string name = context.IidToName(Iid);
            if (!string.IsNullOrEmpty(name))
            {
                return context.FormatPointer(name);
            }
            return $"{context.FormatComment("Unknown IID: {0}", Iid)}{context.FormatPointer("IUnknown")}";
        }
        else
        {
            return $"{context.FormatComment("iid_is param offset: {0}", IidIsDescriptor.Offset)}{context.FormatPointer("IUnknown")}";
        }
    }

    public override int GetSize()
    {
        return IntPtr.Size;
    }
}
#pragma warning restore 1591

