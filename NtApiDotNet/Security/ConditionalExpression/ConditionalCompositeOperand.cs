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

using System.Collections.Generic;
using System.IO;

namespace NtApiDotNet.Security.ConditionalExpression
{
    /// <summary>
    /// Class to represent a composite conditional operand.
    /// </summary>
    public sealed class ConditionalCompositeOperand : ConditionalOperand
    {
        /// <summary>
        /// List of operands.
        /// </summary>
        public List<ConditionalOperand> Operands { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public ConditionalCompositeOperand() 
            : this(new List<ConditionalOperand>())
        {
        }

        internal ConditionalCompositeOperand(List<ConditionalOperand> operands)
        {
            Operands = operands;
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The object as a string.</returns>
        public override string ToString()
        {
            return $"{{{string.Join(",", Operands)}}}";
        }

        internal override void Serialize(BinaryWriter writer)
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter new_writer = new BinaryWriter(stm);
            foreach (var op in Operands)
            {
                op.Serialize(new_writer);
            }
            byte[] result = stm.ToArray();
            writer.Write((byte)0x50);
            writer.Write(result.Length);
            writer.Write(result);
        }
    }
}
