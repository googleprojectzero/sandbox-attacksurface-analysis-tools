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

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NtApiDotNet.Ndr
{
#pragma warning disable 1591
    public enum NdrExpressionType
    {
        FC_EXPR_CONST32 = 0x01,
        FC_EXPR_CONST64 = 0x02,
        FC_EXPR_VAR = 0x03,
        FC_EXPR_OPER = 0x04,
        FC_EXPR_PAD = 0x05,
    }

    public enum NdrExpressionOperator
    {
        OP_UNARY_PLUS = 0x01,
        OP_UNARY_MINUS = 0x02,
        OP_UNARY_NOT = 0x03,
        OP_UNARY_COMPLEMENT = 0x04,
        OP_UNARY_INDIRECTION = 0x05,
        OP_UNARY_CAST = 0x06,
        OP_UNARY_AND = 0x07,
        OP_UNARY_SIZEOF = 0x08,
        OP_UNARY_ALIGNOF = 0x09,
        OP_PRE_INCR = 0x0a,
        OP_PRE_DECR = 0x0b,
        OP_POST_INCR = 0x0c,
        OP_POST_DECR = 0x0d,
        OP_PLUS = 0x0e,
        OP_MINUS = 0x0f,
        OP_STAR = 0x10,
        OP_SLASH = 0x11,
        OP_MOD = 0x12,
        OP_LEFT_SHIFT = 0x13,
        OP_RIGHT_SHIFT = 0x14,
        OP_LESS = 0x15,
        OP_LESS_EQUAL = 0x16,
        OP_GREATER_EQUAL = 0x17,
        OP_GREATER = 0x18,
        OP_EQUAL = 0x19,
        OP_NOT_EQUAL = 0x1A,
        OP_AND = 0x1B,
        OP_OR = 0x1C,
        OP_XOR = 0x1D,
        OP_LOGICAL_AND = 0x1E,
        OP_LOGICAL_OR = 0x1F,
        OP_EXPRESSION = 0x20,
        OP_ASYNCSPLIT = 0x2B,
        OP_CORR_POINTER = 0x2C,
        OP_CORR_TOP_LEVEL = 0x2D,
    }

#pragma warning restore 1591

    /// <summary>
    /// Expression element.
    /// </summary>
    [Serializable]
    public class NdrExpressionElement
    {
        /// <summary>
        /// The expression type.
        /// </summary>
        public NdrExpressionType Type { get; }

        /// <summary>
        /// Is this operator element valid.
        /// </summary>
        public bool IsValid { get; internal set; }

        internal NdrExpressionElement(NdrExpressionType type)
        {
            Type = type;
        }
    }

    /// <summary>
    /// Operator expression element.
    /// </summary>
    [Serializable]
    public sealed class NdrExpressionOperatorElement : NdrExpressionElement
    {
        /// <summary>
        /// NDR format type of element.
        /// </summary>
        public NdrExpressionOperator Operator { get; }

        /// <summary>
        /// NDR format type of element.
        /// </summary>
        public NdrFormatCharacter Format { get; }

        /// <summary>
        /// Padding, probably.
        /// </summary>
        public int Padding { get; }

        internal int ArgumentsTotal { get; }

        /// <summary>
        /// Parsed arguments.
        /// </summary>
        public IReadOnlyCollection<NdrExpressionElement> Arguments { get; private set; }

        internal void SetArguments(Stack<NdrExpressionElement> elements)
        {
            List<NdrExpressionElement> args = new List<NdrExpressionElement>();
            for (int i = 0; i < ArgumentsTotal; ++i)
            {
                args.Insert(0, elements.Pop());
            }
            Arguments = args.AsReadOnly();
        }

        internal NdrExpressionOperatorElement(BinaryReader reader) 
            : base(NdrExpressionType.FC_EXPR_VAR)
        {
            Operator = (NdrExpressionOperator)reader.ReadByte();
            Format = (NdrFormatCharacter)reader.ReadByte();
            Padding = reader.ReadByte();
            Arguments = new List<NdrExpressionElement>().AsReadOnly();

            switch (Operator)
            {
                case NdrExpressionOperator.OP_UNARY_INDIRECTION:
                case NdrExpressionOperator.OP_UNARY_MINUS:
                case NdrExpressionOperator.OP_UNARY_NOT:
                case NdrExpressionOperator.OP_UNARY_PLUS:
                case NdrExpressionOperator.OP_UNARY_CAST:
                    IsValid = true;
                    ArgumentsTotal = 1;
                    break;
                case NdrExpressionOperator.OP_MINUS:
                case NdrExpressionOperator.OP_MOD:
                case NdrExpressionOperator.OP_OR:
                case NdrExpressionOperator.OP_PLUS:
                case NdrExpressionOperator.OP_SLASH:
                case NdrExpressionOperator.OP_STAR:
                case NdrExpressionOperator.OP_XOR:
                case NdrExpressionOperator.OP_AND:
                case NdrExpressionOperator.OP_LEFT_SHIFT:
                case NdrExpressionOperator.OP_RIGHT_SHIFT:
                    IsValid = true;
                    ArgumentsTotal = 2;
                    break;
                default:
                    break;
            }
        }
    }

    /// <summary>
    /// Variable expression element.
    /// </summary>
    [Serializable]
    public sealed class NdrExpressionVariableElement : NdrExpressionElement
    {
        /// <summary>
        /// Offset of the variable.
        /// </summary>
        public int Offset { get; }

        /// <summary>
        /// NDR format type of element.
        /// </summary>
        public NdrFormatCharacter Format { get; }

        internal NdrExpressionVariableElement(BinaryReader reader)
            : base(NdrExpressionType.FC_EXPR_VAR)
        {
            Format = (NdrFormatCharacter)reader.ReadByte();
            Offset = reader.ReadInt16();
            IsValid = true;
        }
    }

    /// <summary>
    /// Expression element.
    /// </summary>
    [Serializable]
    public sealed class NdrExpressionContantElement : NdrExpressionElement
    {
        /// <summary>
        /// NDR format type of element.
        /// </summary>
        public NdrFormatCharacter Format { get; }

        /// <summary>
        /// Offset of the variable.
        /// </summary>
        public int Offset { get; }

        /// <summary>
        /// The value of the constant.
        /// </summary>
        public long Value { get; }

        internal NdrExpressionContantElement(NdrExpressionType type, BinaryReader reader)
            : base(type)
        {
            Format = (NdrFormatCharacter)reader.ReadByte();
            Offset = reader.ReadInt16();
            if (type == NdrExpressionType.FC_EXPR_CONST32)
            {
                Value = reader.ReadInt32();
            }
            else
            {
                Value = reader.ReadInt64();
            }
            IsValid = true;
        }
    }

    /// <summary>
    /// Class to represent an NDR expression.
    /// </summary>
    [Serializable]
    public sealed class NdrExpression
    {
        private static bool IsValidType(NdrExpressionType type)
        {
            switch (type)
            {
                case NdrExpressionType.FC_EXPR_OPER:
                case NdrExpressionType.FC_EXPR_CONST32:
                case NdrExpressionType.FC_EXPR_CONST64:
                case NdrExpressionType.FC_EXPR_VAR:
                    return true;
            }
            return false;
        }

        private static NdrExpressionElement ReadElement(BinaryReader reader)
        {
            NdrExpressionType type = (NdrExpressionType)reader.ReadByte();
            switch (type)
            {
                case NdrExpressionType.FC_EXPR_OPER:
                    return new NdrExpressionOperatorElement(reader);
                case NdrExpressionType.FC_EXPR_CONST32:
                case NdrExpressionType.FC_EXPR_CONST64:
                    return new NdrExpressionContantElement(type, reader);
                case NdrExpressionType.FC_EXPR_VAR:
                    return new NdrExpressionVariableElement(reader);
                default:
                    break;
            }

            return new NdrExpressionElement(0);
        }

        /// <summary>
        /// Indicates if this expression is valid.
        /// </summary>
        public bool IsValid { get; }

        /// <summary>
        /// The root element for the expression.
        /// </summary>
        public NdrExpressionElement RootElement { get; }

        internal NdrExpression()
        {
            RootElement = new NdrExpressionElement(0);
        }

        internal NdrExpression(NdrExpressionElement root_element)
        {
            RootElement = root_element;
            IsValid = true;
        }

        internal static NdrExpression Read(NdrParseContext context, int index)
        {
            if (context.ExprDesc.pOffset == IntPtr.Zero || context.ExprDesc.pFormatExpr == IntPtr.Zero || index < 0)
            {
                return new NdrExpression();
            }

            int expr_ofs = context.Reader.ReadInt16(context.ExprDesc.pOffset + (2 * index));
            if (expr_ofs < 0)
            {
                return new NdrExpression();
            }

            BinaryReader reader = context.Reader.GetReader(context.ExprDesc.pFormatExpr + expr_ofs);
            List<NdrExpressionElement> elements = new List<NdrExpressionElement>();
            Stack<NdrExpressionOperatorElement> operator_stack = new Stack<NdrExpressionOperatorElement>();
            Stack<NdrExpressionElement> value_stack = new Stack<NdrExpressionElement>();
            bool is_valid = true;

            do
            {
                NdrExpressionElement element = ReadElement(reader);

                // TODO: Implement OP_EXPRESSION.
                if (!element.IsValid)
                {
                    is_valid = false;
                    break;
                }

                elements.Add(element);
                if (element is NdrExpressionOperatorElement op)
                {
                    operator_stack.Push(op);
                }
                else
                {
                    value_stack.Push(element);
                    if (operator_stack.Count > 0 && value_stack.Count >= operator_stack.Peek().ArgumentsTotal)
                    {
                        var curr_op = operator_stack.Pop();
                        curr_op.SetArguments(value_stack);
                        value_stack.Push(curr_op);
                    }
                }
            }
            while (operator_stack.Count > 0);

            // There should only be one value left on the stack, if not don't trust it.
            if (!is_valid || value_stack.Count != 1)
            {
                return new NdrExpression();
            }

            return new NdrExpression(value_stack.Pop());
        }
    }
}
