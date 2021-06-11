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
    /// Size of conditional integer operand.
    /// </summary>
    public enum ConditionalIntegerSize
    {
        Byte,
        Short,
        Dword,
        Qword,
    }

    /// <summary>
    /// Sign of conditional integer operand.
    /// </summary>
    public enum ConditionalIntegerSign
    {
        None,
        Positive,
        Negative
    }

    /// <summary>
    /// Base of conditional integer operand.
    /// </summary>
    public enum ConditionalIntegerBase
    {
        Octal,
        Decimal,
        Hexadecimal
    }
#pragma warning restore 1591

    /// <summary>
    /// Class to represent a conditional integer operand.
    /// </summary>
    public sealed class ConditionalIntegerOperand : ConditionalOperand
    {
        /// <summary>
        /// Size of the integer.
        /// </summary>
        public ConditionalIntegerSize Size { get; set; }
        /// <summary>
        /// Value of the integer.
        /// </summary>
        public long Value { get; set; }
        /// <summary>
        /// Sign of the integer.
        /// </summary>
        public ConditionalIntegerSign Sign { get; set; }
        /// <summary>
        /// Base of the integer.
        /// </summary>
        public ConditionalIntegerBase Base { get; set; }

        internal static bool Parse(byte byte_code, BinaryReader reader, out ConditionalIntegerOperand operand)
        {
            operand = new ConditionalIntegerOperand();
            switch (byte_code)
            {
                case 0x01:
                    operand.Size = ConditionalIntegerSize.Byte;
                    break;
                case 0x02:
                    operand.Size = ConditionalIntegerSize.Short;
                    break;
                case 0x03:
                    operand.Size = ConditionalIntegerSize.Dword;
                    break;
                case 0x04:
                    operand.Size = ConditionalIntegerSize.Qword;
                    break;
                default:
                    return false;
            }
            operand.Value = reader.ReadInt64();

            switch (reader.ReadByte())
            {
                case 0x01:
                    operand.Sign = ConditionalIntegerSign.Positive;
                    break;
                case 0x02:
                    operand.Sign = ConditionalIntegerSign.Negative;
                    break;
                case 0x03:
                    operand.Sign = ConditionalIntegerSign.None;
                    break;
                default:
                    return false;
            }

            switch (reader.ReadByte())
            {
                case 0x01:
                    operand.Base = ConditionalIntegerBase.Octal;
                    break;
                case 0x02:
                    operand.Base = ConditionalIntegerBase.Decimal;
                    break;
                case 0x03:
                    operand.Base = ConditionalIntegerBase.Hexadecimal;
                    break;
                default:
                    return false;
            }

            return true;
        }

        internal override void Serialize(BinaryWriter writer)
        {
            switch (Size)
            {
                case ConditionalIntegerSize.Byte:
                    writer.Write((byte)0x01);
                    break;
                case ConditionalIntegerSize.Short:
                    writer.Write((byte)0x02);
                    break;
                case ConditionalIntegerSize.Dword:
                    writer.Write((byte)0x03);
                    break;
                case ConditionalIntegerSize.Qword:
                    writer.Write((byte)0x04);
                    break;
                default:
                    throw new ArgumentException("Invalid size value", nameof(Size));
            }

            writer.Write(Value);
            switch (Sign)
            {
                case ConditionalIntegerSign.Positive:
                    writer.Write((byte)0x01);
                    break;
                case ConditionalIntegerSign.Negative:
                    writer.Write((byte)0x02);
                    break;
                case ConditionalIntegerSign.None:
                    writer.Write((byte)0x03);
                    break;
                default:
                    throw new ArgumentException("Invalid sign value", nameof(Sign));
            }
            switch (Base)
            {
                case ConditionalIntegerBase.Octal:
                    writer.Write((byte)0x01);
                    break;
                case ConditionalIntegerBase.Decimal:
                    writer.Write((byte)0x02);
                    break;
                case ConditionalIntegerBase.Hexadecimal:
                    writer.Write((byte)0x03);
                    break;
                default:
                    throw new ArgumentException("Invalid basevalue", nameof(Base));
            }
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public ConditionalIntegerOperand()
        {
            Size = ConditionalIntegerSize.Qword;
            Base = ConditionalIntegerBase.Decimal;
            Sign = ConditionalIntegerSign.None;
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The object as a string.</returns>
        public override string ToString()
        {
            string value;
            switch (Base)
            {
                case ConditionalIntegerBase.Hexadecimal:
                    value = $"0x{Value:X}";
                    break;
                case ConditionalIntegerBase.Octal:
                    value = "0"+Convert.ToString(Value, 8);
                    break;
                default:
                    value = Value.ToString();
                    break;
            }

            switch (Sign)
            {
                case ConditionalIntegerSign.Positive:
                    value = $"+{value}";
                    break;
            }
            return value;
        }
    }
}
