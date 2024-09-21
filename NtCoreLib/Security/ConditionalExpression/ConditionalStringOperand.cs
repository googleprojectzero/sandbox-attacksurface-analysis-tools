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

using System.IO;
using System.Text;

namespace NtApiDotNet.Security.ConditionalExpression
{
    /// <summary>
    /// Class to represent a string conditional operand.
    /// </summary>
    public sealed class ConditionalStringOperand : ConditionalOperand
    {
        /// <summary>
        /// The string value.
        /// </summary>
        public string Value { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="value">The string value.</param>
        public ConditionalStringOperand(string value)
        {
            Value = value;
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The object as a string.</returns>
        public override string ToString()
        {
            return Value;
        }

        internal override void Serialize(BinaryWriter writer)
        {
            byte[] str = Encoding.Unicode.GetBytes(Value);
            writer.Write((byte)0x10);
            writer.Write(str.Length);
            writer.Write(str);
        }
    }
}
