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
using System.Text;

namespace NtApiDotNet.Security.ConditionalExpression
{
#pragma warning disable 1591
    /// <summary>
    /// The type of the security attribute name.
    /// </summary>
    public enum ConditionalAttributeNameType
    {
        Local,
        User,
        Resource,
        Device
    }
#pragma warning restore 1591

    /// <summary>
    /// Class to represent an attribute name operand.
    /// </summary>
    public sealed class ConditionalAttributeOperand : ConditionalOperand
    {
        /// <summary>
        /// The type of attribute.
        /// </summary>
        public ConditionalAttributeNameType Type { get; set; }

        /// <summary>
        /// The name of the attribute.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="type">The type of the attribute.</param>
        /// <param name="name">The name of the attribute.</param>
        public ConditionalAttributeOperand(ConditionalAttributeNameType type, string name)
        {
            Type = type;
            Name = name;
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The object as a string.</returns>
        public override string ToString()
        {
            switch (Type)
            {
                case ConditionalAttributeNameType.Device:
                    return $"@Device.{Name}";
                case ConditionalAttributeNameType.User:
                    return $"@User.{Name}";
                case ConditionalAttributeNameType.Resource:
                    return $"@Resource.{Name}";
                default:
                    return Name;
            }
        }

        internal override void Serialize(BinaryWriter writer)
        {
            switch (Type)
            {
                case ConditionalAttributeNameType.Local:
                    writer.Write((byte)0xF8);
                    break;
                case ConditionalAttributeNameType.User:
                    writer.Write((byte)0xF9);
                    break;
                case ConditionalAttributeNameType.Resource:
                    writer.Write((byte)0xFA);
                    break;
                case ConditionalAttributeNameType.Device:
                    writer.Write((byte)0xFB);
                    break;
                default:
                    throw new ArgumentException("Invalid attribute type", nameof(Type));
            }
            byte[] data = Encoding.Unicode.GetBytes(Name);
            writer.Write(data.Length);
            writer.Write(data);
        }
    }
}
