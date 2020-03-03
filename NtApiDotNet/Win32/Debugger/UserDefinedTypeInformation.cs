//  Copyright 2020 Google Inc. All Rights Reserved.
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

using System.Collections.Generic;

namespace NtApiDotNet.Win32.Debugger
{
    /// <summary>
    /// Represents a member of a UDT.
    /// </summary>
    public class UserDefinedTypeMember
    {
        /// <summary>
        /// The type of the member.
        /// </summary>
        public TypeInformation Type { get; }
        /// <summary>
        /// The name of the member.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// The offset into the UDT.
        /// </summary>
        public int Offset { get; }
        /// <summary>
        /// The size of the member.
        /// </summary>
        public long Size => Type.Size;

        internal UserDefinedTypeMember(TypeInformation type, string name, int offset)
        {
            Type = type;
            Name = name;
            Offset = offset;
        }
    }

    /// <summary>
    /// Represents a bit field member of a UDT.
    /// </summary>
    public class UserDefinedTypeBitFieldMember : UserDefinedTypeMember
    {
        /// <summary>
        /// If a bit field then this is the bit start position.
        /// </summary>
        public int BitPosition { get; }
        /// <summary>
        /// If a bit field this is the bit length.
        /// </summary>
        public int BitLength { get; }

        internal UserDefinedTypeBitFieldMember(TypeInformation type, string name, int offset, int bit_position, long bit_length) 
            : base(type, name, offset)
        {
            BitPosition = bit_position;
            BitLength = (int)bit_length;
        }
    }

    /// <summary>
    /// Symbol information for an enumerated type.
    /// </summary>
    public class UserDefinedTypeInformation : TypeInformation
    {
        /// <summary>
        /// The members of the UDT.
        /// </summary>
        public ICollection<UserDefinedTypeMember> Members { get; }

        /// <summary>
        /// Indicates the UDT is a union.
        /// </summary>
        public bool Union { get; }

        internal UserDefinedTypeInformation(long size, int type_index, SymbolLoadedModule module, 
            string name, bool union, ICollection<UserDefinedTypeMember> members)
            : base(SymTagEnum.SymTagUDT, size, type_index, module, name)
        {
            Members = members;
            Union = union;
        }
    }
}
