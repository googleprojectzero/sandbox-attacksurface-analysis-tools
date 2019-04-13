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

using System;
using System.IO;

namespace NtApiDotNet.Ndr
{
#pragma warning disable 1591
    [Flags]
    [Serializable]
    public enum NdrCorrelationType : byte
    {
        FC_NORMAL_CONFORMANCE = 0,
        FC_POINTER_CONFORMANCE = 0x10,
        FC_TOP_LEVEL_CONFORMANCE = 0x20,
        FC_CONSTANT_CONFORMANCE = 0x40,
        FC_TOP_LEVEL_MULTID_CONFORMANCE = 0x80,
    }

    [Flags]
    [Serializable]
    public enum NdrCorrelationFlags : byte
    {
        Early = 0x1,
        Split = 0x2,
        IsIidIs = 0x4,
        DontCheck = 0x8,
        Range = 0x10,
    }

    [Serializable]
    public sealed class NdrCorrelationDescriptorRange
    {
        public bool IsValid { get; }
        public int MinValue { get; }
        public int MaxValue { get; }

        internal NdrCorrelationDescriptorRange()
        {
        }

        internal NdrCorrelationDescriptorRange(BinaryReader reader)
        {
            IsValid = (reader.ReadByte() & 1) != 0;
            reader.ReadByte(); // Padding?
            MinValue = reader.ReadInt32();
            MaxValue = reader.ReadInt32();
        }
    }

    [Serializable]
    public sealed class NdrCorrelationDescriptor
    {
        public NdrCorrelationType CorrelationType { get; private set; }
        public NdrFormatCharacter ValueType { get; private set; }
        public NdrFormatCharacter Operator { get; private set; }
        public int Offset { get; private set; }
        public NdrCorrelationFlags Flags { get; private set; }
        public bool IsValid { get; private set; }
        public NdrCorrelationDescriptorRange Range { get; private set; }
        public NdrExpression Expression { get; private set; }
        public bool IsConstant => CorrelationType == NdrCorrelationType.FC_CONSTANT_CONFORMANCE;
        public bool IsNormal => CorrelationType == NdrCorrelationType.FC_NORMAL_CONFORMANCE;
        public bool IsTopLevel => CorrelationType == NdrCorrelationType.FC_TOP_LEVEL_CONFORMANCE;
        public bool IsPointer => CorrelationType == NdrCorrelationType.FC_POINTER_CONFORMANCE;

        internal NdrCorrelationDescriptor()
        {
            Range = new NdrCorrelationDescriptorRange();
            Expression = new NdrExpression();
        }

        internal NdrCorrelationDescriptor(NdrParseContext context, BinaryReader reader) : this()
        {
            byte type_byte = reader.ReadByte();
            byte op_byte = reader.ReadByte();
            int offset = reader.ReadInt16();
            int flags = 0;
            if (context.OptFlags.HasFlag(NdrInterpreterOptFlags2.HasNewCorrDesc) || context.OptFlags.HasFlag(NdrInterpreterOptFlags2.HasRangeOnConformance))
            {
                flags = reader.ReadInt16();
                // Read out the range.
                if (context.OptFlags.HasFlag(NdrInterpreterOptFlags2.HasRangeOnConformance))
                {
                    Range = new NdrCorrelationDescriptorRange(reader);
                    System.Diagnostics.Debug.Assert(((flags & 0x10) == 0x10) == Range.IsValid);
                }
            }

            if (type_byte != 0xFF || op_byte != 0xFF || offset != -1)
            {
                IsValid = true;
                CorrelationType = (NdrCorrelationType)(type_byte & 0xF0);
                ValueType = (NdrFormatCharacter)(type_byte & 0xF);
                Operator = (NdrFormatCharacter)op_byte;
                Offset = offset;
                Flags = (NdrCorrelationFlags)flags;
                if (IsConstant)
                {
                    Offset |= (op_byte << 16);
                    Operator = NdrFormatCharacter.FC_ZERO;
                }
                else
                {
                    if (Operator == NdrFormatCharacter.FC_EXPR)
                    {
                        Expression = NdrExpression.Read(context, offset);
                    }
                }
            }
        }

        public override string ToString()
        {
            if (IsValid)
            {
                string expr = (Operator == NdrFormatCharacter.FC_EXPR) && Expression.IsValid ? Expression.ToString() : Operator.ToString();
                return $"({CorrelationType})({Offset})({expr})({ValueType})({Flags})";
            }
            return string.Empty;
        }
    }
#pragma warning restore 1591
}
