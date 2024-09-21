//  Copyright 2021 Google LLC. All Rights Reserved.
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

using System;
using System.IO;

namespace NtApiDotNet.Security.ConditionalExpression
{
#pragma warning disable 1591
    /// <summary>
    /// Conditional operator type.
    /// </summary>
    public enum ConditionalOperatorType : byte
    {
        Equals = 0x80,
        NotEquals = 0x81,
        LessThan = 0x82,
        LessThanOrEqual = 0x83,
        GreaterThan = 0x84,
        GreaterThanOrEqual = 0x85,
        Contains = 0x86,
        Exists = 0x87,
        NotExists = 0x8D,
        AnyOf = 0x88,
        MemberOf = 0x89,
        DeviceMemberOf = 0x8A,
        MemberOfAny = 0x8B,
        DeviceMemberOfAny = 0x8C,
        NotContains = 0x8E,
        NotAnyOf = 0x8F,
        NotMemberOf = 0x90,
        NotDeviceMemberOf = 0x91,
        NotMemberOfAny = 0x92,
        NotDeviceMemberOfAny = 0x93,
        LogicalAnd = 0xA0,
        LogicalOr = 0xA1,
        LogicalNot = 0xA2,
    }
#pragma warning restore 1591

    /// <summary>
    /// Class to represent a conditional operator operand.
    /// </summary>
    public sealed class ConditionalOperatorOperand : ConditionalOperand
    {
        /// <summary>
        /// The type of operator.
        /// </summary>
        public ConditionalOperatorType Type { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="type">The type of operator.</param>
        public ConditionalOperatorOperand(ConditionalOperatorType type)
        {
            Type = type;
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The object as a string.</returns>
        public override string ToString()
        {
            return Type.ToString();
        }

        internal override void Serialize(BinaryWriter writer)
        {
            if (!Enum.IsDefined(typeof(ConditionalOperatorType), Type))
            {
                throw new ArgumentException("Invalid operator type", nameof(Type));
            }
            writer.Write((byte)Type);
        }
    }
}
