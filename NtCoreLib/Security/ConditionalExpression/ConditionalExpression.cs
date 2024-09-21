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
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NtApiDotNet.Security.ConditionalExpression
{
    /// <summary>
    /// Class to represent a conditional expression.
    /// </summary>
    public sealed class ConditionalExpression
    {
        #region Private Members
        private const int BINARY_MAGIC = 0x78747261;

        private static string ReadString(BinaryReader reader)
        {
            return Encoding.Unicode.GetString(ReadBytes(reader));
        }

        private static byte[] ReadBytes(BinaryReader reader)
        {
            int length = reader.ReadInt32();
            return reader.ReadAllBytes(length);
        }

        private static bool Parse(byte token, BinaryReader reader, List<ConditionalOperand> operands)
        {
            if (Enum.IsDefined(typeof(ConditionalOperatorType), token))
            {
                operands.Add(new ConditionalOperatorOperand((ConditionalOperatorType)token));
                return true;
            }
            
            switch (token)
            {
                case 0xF8:
                    operands.Add(new ConditionalAttributeOperand(ConditionalAttributeNameType.Local, ReadString(reader)));
                    break;
                case 0xF9:
                    operands.Add(new ConditionalAttributeOperand(ConditionalAttributeNameType.User, ReadString(reader)));
                    break;
                case 0xFA:
                    operands.Add(new ConditionalAttributeOperand(ConditionalAttributeNameType.Resource, ReadString(reader)));
                    break;
                case 0xFB:
                    operands.Add(new ConditionalAttributeOperand(ConditionalAttributeNameType.Device, ReadString(reader)));
                    break;
                default:
                    return false;
            }
            return true;
        }

        private static bool Parse(byte[] data, bool expression, out List<ConditionalOperand> operands)
        {
            operands = new List<ConditionalOperand>();
            BinaryReader reader = new BinaryReader(new MemoryStream(data));
            if (expression && reader.ReadUInt32() != BINARY_MAGIC)
            {
                return false;
            }

            while (reader.BaseStream.Position < reader.BaseStream.Length)
            {
                byte token = reader.ReadByte();
                switch (token)
                {
                    case 0x00:
                        break;
                    case 0x01:
                    case 0x02:
                    case 0x03:
                    case 0x04:
                        if (!ConditionalIntegerOperand.Parse(token, reader, out ConditionalIntegerOperand int_op))
                        {
                            return false;
                        }
                        operands.Add(int_op);
                        break;
                    case 0x10:
                        operands.Add(new ConditionalStringOperand(ReadString(reader)));
                        break;
                    case 0x18:
                        operands.Add(new ConditionalOctetStringOperand(ReadBytes(reader)));
                        break;
                    case 0x50:
                        if (!Parse(ReadBytes(reader), false, out List<ConditionalOperand> comp_ops))
                        {
                            return false;
                        }
                        operands.Add(new ConditionalCompositeOperand(comp_ops));
                        break;
                    case 0x51:
                        var sid = Sid.Parse(ReadBytes(reader), false);
                        if (!sid.IsSuccess)
                        {
                            return false;
                        }
                        operands.Add(new ConditionalSidOperand(sid.Result));
                        break;
                    default:
                        if (!expression || !Parse(token, reader, operands))
                        {
                            return false;
                        }
                        break;
                }
            }
            return true;
        }

        private ConditionalExpression(List<ConditionalOperand> operands)
        {
            Operands = operands;
        }

        #endregion

        #region Public Methods
        /// <summary>
        /// Serialize the expression to a byte array.
        /// </summary>
        /// <returns>The expression as a byte array.</returns>
        public byte[] ToByteArray()
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            writer.Write(BINARY_MAGIC);
            foreach (var op in Operands)
            {
                op.Serialize(writer);
            }

            long remaining = stm.Length & 3;
            if (remaining > 0)
            {
                writer.Write(new byte[4 - remaining]);
            }
            return stm.ToArray();
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The object as a string.</returns>
        public override string ToString()
        {
            return string.Join(", ", Operands);
        }

        #endregion

        #region Static Methods
        /// <summary>
        /// Parse a binary conditional expression.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The parsed conditional expression.</returns>
        public static NtResult<ConditionalExpression> Parse(byte[] data, bool throw_on_error)
        {
            try
            {
                if (Parse(data, true, out List<ConditionalOperand> operands))
                {
                    return new ConditionalExpression(operands).CreateResult();
                }
            }
            catch (EndOfStreamException)
            {
            }
            return NtStatus.STATUS_INVALID_ACE_CONDITION.CreateResultFromError<ConditionalExpression>(throw_on_error);
        }

        /// <summary>
        /// Parse a binary conditional expression.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <returns>The parsed conditional expression.</returns>
        public static ConditionalExpression Parse(byte[] data)
        {
            return Parse(data, true).Result;
        }

        /// <summary>
        /// Parse an SDDL conditional expression.
        /// </summary>
        /// <param name="condition_sddl">The SDDL expression to parse.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The parsed conditional expression.</returns>
        public static NtResult<ConditionalExpression> Parse(string condition_sddl, bool throw_on_error)
        {
            var sd = SecurityDescriptor.Parse($"D:(XA;;1;;;WD;({condition_sddl}))", throw_on_error);
            if (!sd.IsSuccess)
            {
                return sd.Cast<ConditionalExpression>();
            }
            return Parse(sd.Result.Dacl[0].ApplicationData, throw_on_error);
        }

        /// <summary>
        /// Parse an SDDL conditional expression.
        /// </summary>
        /// <param name="condition_sddl">The SDDL expression to parse.</param>
        /// <returns>The parsed conditional expression.</returns>
        public static ConditionalExpression Parse(string condition_sddl)
        {
            return Parse(condition_sddl, true).Result;
        }

        #endregion

        #region Public Properties
        /// <summary>
        /// Get list of the conditional operands.
        /// </summary>
        public List<ConditionalOperand> Operands { get; }
        #endregion
    }
}
