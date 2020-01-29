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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace NtApiDotNet.Ndr
{
#pragma warning disable 1591

    [Serializable]
    public abstract class NdrComplexTypeReference : NdrBaseTypeReference
    {
        public string Name { get; set; }
        internal abstract string FormatComplexType(INdrFormatterInternal context);

        internal NdrComplexTypeReference(string name, NdrFormatCharacter format) : base(format)
        {
            Name = name;
        }
    }

    [Serializable]
    public sealed class NdrStructureMember
    {
        public NdrBaseTypeReference MemberType { get; internal set; }
        public int Offset { get; private set; }
        public string Name { get; set; }

        internal NdrStructureMember(NdrBaseTypeReference member_type, int offset, string name)
        {
            MemberType = member_type;
            Offset = offset;
            Name = name;
        }

        internal string FormatMember(INdrFormatterInternal context)
        {
            return $"{context.FormatComment("Offset: {0}", Offset)} {MemberType.FormatType(context)}";
        }

        internal void FixupLateBoundTypes()
        {
            MemberType = NdrBaseTypeReference.GetIndirectType(MemberType);
        }
    }

    [Serializable]
    public class NdrBaseStructureTypeReference : NdrComplexTypeReference
    {
        protected List<NdrBaseTypeReference> _base_members;
        private List<NdrStructureMember> _members;

        public int Alignment { get; }
        public int MemorySize { get; }
        public virtual bool Conformant => false;

        protected virtual List<NdrStructureMember> PopulateMembers()
        {
            List<NdrStructureMember> members = new List<NdrStructureMember>();
            int current_offset = 0;
            foreach (var type in _base_members)
            {
                if (!(type is NdrStructurePaddingTypeReference) && !(type is NdrIgnoreTypeReference))
                {
                    members.Add(new NdrStructureMember(type, current_offset, $"Member{current_offset:X}"));
                }
                current_offset += type.GetSize();
            }
            return members;
        }

        private List<NdrStructureMember> GetMembers()
        {
            if (_members == null)
            {
                _members = PopulateMembers();
            }
            return _members;
        }

        public IEnumerable<NdrBaseTypeReference> MembersTypes { get { return _base_members.AsReadOnly(); } }

        public IEnumerable<NdrStructureMember> Members => GetMembers().AsReadOnly();

        internal NdrBaseStructureTypeReference(NdrParseContext context, NdrFormatCharacter format, BinaryReader reader)
            : base($"Struct_{context.TypeCache.GetNextComplexId()}", format)
        {
            Alignment = reader.ReadByte();
            MemorySize = reader.ReadUInt16();
            _base_members = new List<NdrBaseTypeReference>();
        }

        internal void ReadMemberInfo(NdrParseContext context, BinaryReader reader)
        {
            NdrBaseTypeReference curr_type;
            while ((curr_type = Read(context, reader)) != null)
            {
                _base_members.Add(curr_type);
            }
        }

        internal override string FormatType(INdrFormatterInternal context)
        {
            return $"struct {Name}";
        }

        internal override string FormatComplexType(INdrFormatterInternal context)
        {
            StringBuilder builder = new StringBuilder();
            builder.Append(context.FormatComment("Memory Size: {0}", GetSize())).AppendLine();
            builder.Append(FormatType(context)).AppendLine(" {");
            foreach (var member in Members.Select((m, i) => $"{m.FormatMember(context)} {m.Name}"))
            {
                builder.Append("    ").Append(member).AppendLine(";");
            }
            builder.AppendLine("};");
            return builder.ToString();
        }

        public override int GetSize()
        {
            return MemorySize;
        }

        protected override void OnFixupLateBoundTypes()
        {
            foreach (var member in _base_members)
            {
                member.FixupLateBoundTypes();
            }
        }
    }

    [Serializable]
    public sealed class NdrSimpleStructureTypeReference : NdrBaseStructureTypeReference
    {
        internal NdrSimpleStructureTypeReference(NdrParseContext context, BinaryReader reader)
            : base(context, NdrFormatCharacter.FC_STRUCT, reader)
        {
            ReadMemberInfo(context, reader);
        }
    }

    [Serializable]
    public sealed class NdrSimpleStructureWithPointersTypeReference : NdrBaseStructureTypeReference
    {
        public NdrPointerInfoTypeReference PointerInfo { get; }

        internal NdrSimpleStructureWithPointersTypeReference(NdrParseContext context, BinaryReader reader)
            : base(context, NdrFormatCharacter.FC_PSTRUCT, reader)
        {
            // Read out FC_PP type.
            reader.ReadByte();
            PointerInfo = new NdrPointerInfoTypeReference(context, reader);
            ReadMemberInfo(context, reader);
        }

        protected override List<NdrStructureMember> PopulateMembers()
        {
            var members = base.PopulateMembers();
            var pointer_types = PointerInfo.PointerInstances.ToDictionary(p => p.OffsetInMemory);

            foreach (var member in members)
            {
                if (pointer_types.ContainsKey(member.Offset))
                {
                    member.MemberType = pointer_types[member.Offset].PointerType;
                }
            }

            return members;
        }
    }

    [Serializable]
    public sealed class NdrConformantStructureTypeReference : NdrBaseStructureTypeReference
    {
        public NdrBaseTypeReference ConformantArray { get; }

        public override bool Conformant => true;

        internal NdrConformantStructureTypeReference(NdrFormatCharacter format, NdrParseContext context, BinaryReader reader)
            : base(context, format, reader)
        {
            ConformantArray = Read(context, ReadTypeOffset(reader));
            ReadMemberInfo(context, reader);
        }

        protected override List<NdrStructureMember> PopulateMembers()
        {
            var last_member = _base_members.LastOrDefault() as NdrBaseStructureTypeReference;
            if (last_member == null || !last_member.Conformant)
            {
                _base_members.Add(ConformantArray);
            }

            return base.PopulateMembers();
        }
    }

    [Serializable]
    public sealed class NdrBogusStructureTypeReference : NdrBaseStructureTypeReference
    {
        public NdrBaseTypeReference ConformantArray { get; }

        public override bool Conformant => ConformantArray != null;

        internal NdrBogusStructureTypeReference(NdrParseContext context, NdrFormatCharacter format, BinaryReader reader)
            : base(context, format, reader)
        {
            ConformantArray = Read(context, ReadTypeOffset(reader));
            int pointer_ofs = ReadTypeOffset(reader);
            ReadMemberInfo(context, reader);
            if (pointer_ofs >= 0)
            {
                BinaryReader pointer_reader = GetReader(context, pointer_ofs);
                for (int i = 0; i < _base_members.Count; ++i)
                {
                    if (_base_members[i].Format == NdrFormatCharacter.FC_POINTER)
                    {
                        _base_members[i] = Read(context, reader);
                    }
                }
            }
        }

        protected override List<NdrStructureMember> PopulateMembers()
        {
            if (ConformantArray != null)
            {
                var last_member = _base_members.LastOrDefault() as NdrBaseStructureTypeReference;
                if (last_member == null || !last_member.Conformant)
                {
                    _base_members.Add(ConformantArray);
                }
            }

            return base.PopulateMembers();
        }
    }

    [Serializable]
    public sealed class NdrIgnoreTypeReference : NdrBaseTypeReference
    {
        internal NdrIgnoreTypeReference() : base(NdrFormatCharacter.FC_IGNORE)
        {
        }
    }

    [Serializable]
    public sealed class NdrStructurePaddingTypeReference : NdrBaseTypeReference
    {
        internal NdrStructurePaddingTypeReference(NdrFormatCharacter format) : base(format)
        {
        }

        public override int GetSize()
        {
            switch (Format)
            {
                case NdrFormatCharacter.FC_STRUCTPAD1:
                    return 1;
                case NdrFormatCharacter.FC_STRUCTPAD2:
                    return 2;
                case NdrFormatCharacter.FC_STRUCTPAD3:
                    return 3;
                case NdrFormatCharacter.FC_STRUCTPAD4:
                    return 4;
                case NdrFormatCharacter.FC_STRUCTPAD5:
                    return 5;
                case NdrFormatCharacter.FC_STRUCTPAD6:
                    return 6;
                case NdrFormatCharacter.FC_STRUCTPAD7:
                    return 7;
                default:
                    throw new InvalidOperationException("Format must be a padding character");
            }
        }
    }

    [Serializable]
    public sealed class NdrPointerInfoInstance
    {
        public int OffsetInMemory { get; }
        public int OffsetInBuffer { get; }
        public NdrPointerTypeReference PointerType { get; }

        internal NdrPointerInfoInstance(NdrParseContext context, BinaryReader reader)
        {
            OffsetInMemory = reader.ReadInt16();
            OffsetInBuffer = reader.ReadInt16();
            PointerType = NdrBaseTypeReference.Read(context, reader) as NdrPointerTypeReference;
        }
    }

    [Serializable]
    public sealed class NdrPointerInfoTypeReference : NdrBaseTypeReference
    {
        public NdrFormatCharacter BasePointerType { get; }
        public NdrFormatCharacter SubPointerType { get; }
        public int Iterations { get; private set; }
        public int Increment { get; private set; }
        public int OffsetToArray { get; private set; }
        public IEnumerable<NdrPointerInfoInstance> PointerInstances { get; }

        private IEnumerable<NdrPointerInfoInstance> ReadComplex(NdrParseContext context, BinaryReader reader, bool has_interations)
        {
            if (has_interations)
            {
                Iterations = reader.ReadInt16();
            }

            Increment = reader.ReadInt16();
            OffsetToArray = reader.ReadInt16();
            int num_of_pointers = reader.ReadInt16();
            while (num_of_pointers > 0)
            {
                yield return new NdrPointerInfoInstance(context, reader);
                num_of_pointers--;
            }
        }

        internal NdrPointerInfoTypeReference(NdrParseContext context, BinaryReader reader)
            : base(NdrFormatCharacter.FC_PP)
        {
            List<NdrPointerInfoInstance> instances = new List<NdrPointerInfoInstance>();
            reader.ReadByte(); // Padding.
            BasePointerType = (NdrFormatCharacter)reader.ReadByte();
            SubPointerType = (NdrFormatCharacter)reader.ReadByte();

            switch (BasePointerType)
            {
                case NdrFormatCharacter.FC_NO_REPEAT:
                    instances.Add(new NdrPointerInfoInstance(context, reader));
                    break;
                case NdrFormatCharacter.FC_FIXED_REPEAT:
                    instances.AddRange(ReadComplex(context, reader, true));
                    break;
                case NdrFormatCharacter.FC_VARIABLE_REPEAT:
                    instances.AddRange(ReadComplex(context, reader, false));
                    break;
            }

            while ((NdrFormatCharacter)reader.ReadByte() != NdrFormatCharacter.FC_END)
            {
            }

            PointerInstances = instances;
        }
    }

#pragma warning restore 1591
}
