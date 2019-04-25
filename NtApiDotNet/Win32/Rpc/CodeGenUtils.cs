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

using NtApiDotNet.Ndr;
using NtApiDotNet.Ndr.Marshal;
using System;
using System.CodeDom;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace NtApiDotNet.Win32.Rpc
{
    [Serializable]
    internal sealed class ComplexTypeMember
    {
        public NdrBaseTypeReference MemberType { get; }
        public int Offset { get; }
        public string Name { get; }
        public CodeExpression Selector { get; }
        public bool Default { get; }
        public bool Hidden { get; }

        internal ComplexTypeMember(NdrBaseTypeReference member_type, int offset, string name, CodeExpression selector, bool default_arm, bool hidden)
        {
            MemberType = member_type;
            Offset = offset;
            Name = name;
            Selector = selector;
            Default = default_arm;
            Hidden = hidden;
        }
    }

    internal static class CodeGenUtils
    {
        #region Private Members

        private static Regex _identifier_regex = new Regex(@"[^a-zA-Z0-9_\.]");

        private static void AddMarshalInterfaceMethod(CodeTypeDeclaration type, MarshalHelperBuilder marshal_helper, bool non_encapsulated_union)
        {
            CodeMemberMethod method = type.AddMethod(nameof(INdrStructure.Marshal), MemberAttributes.Final | MemberAttributes.Private);
            method.PrivateImplementationType = new CodeTypeReference(typeof(INdrStructure));
            method.AddParam(typeof(NdrMarshalBuffer), "m");
            if (non_encapsulated_union)
            {
                method.AddThrow(typeof(NotImplementedException));
            }
            else
            {
                method.Statements.Add(new CodeMethodInvokeExpression(new CodeMethodReferenceExpression(null, nameof(INdrStructure.Marshal)),
                    marshal_helper.CastMarshal(GetVariable("m"))));
            }
        }

        private static void AddMarshalUnionInterfaceMethod(CodeTypeDeclaration type, MarshalHelperBuilder marshal_helper, string selector_name, CodeTypeReference selector_type)
        {
            CodeMemberMethod method = type.AddMethod(nameof(INdrNonEncapsulatedUnion.Marshal), MemberAttributes.Final | MemberAttributes.Private);
            method.PrivateImplementationType = new CodeTypeReference(typeof(INdrNonEncapsulatedUnion));
            method.AddParam(typeof(NdrMarshalBuffer), "m");
            method.AddParam(typeof(long), "l");
            // Assign the hidden selector.
            method.Statements.Add(new CodeAssignStatement(GetVariable(selector_name), new CodeCastExpression(selector_type, GetVariable("l"))));
            method.Statements.Add(new CodeMethodInvokeExpression(new CodeMethodReferenceExpression(null, nameof(INdrStructure.Marshal)),
                marshal_helper.CastMarshal(GetVariable("m"))));
        }

        private static void AddAssignmentStatements(this CodeMemberMethod method, CodeExpression target, IEnumerable<Tuple<CodeTypeReference, string, bool>> parameters)
        {
            foreach (var p in parameters)
            {
                method.AddParam(p.Item1, p.Item2);
                method.Statements.Add(new CodeAssignStatement(target.GetFieldReference(p.Item2), GetVariable(p.Item2)));
            }
        }

        private static string FormatCaseLabel(NdrUnionArm arm)
        {
            if (arm.CaseValue < 0)
            {
                return $"minus_{-arm.CaseValue}";
            }
            return arm.CaseValue.ToString();
        }

        private static CodeExpression GetArmCase(this NdrUnionArm arm, NdrSimpleTypeReference ndr_type)
        {
            long ret = arm.CaseValue;
            switch (ndr_type.Format)
            {
                case NdrFormatCharacter.FC_BYTE:
                    ret = (byte)arm.CaseValue;
                    break;
                case NdrFormatCharacter.FC_USHORT:
                    ret = (ushort)arm.CaseValue;
                    break;
                case NdrFormatCharacter.FC_ULONG:
                    ret = (uint)arm.CaseValue;
                    break;
            }
            return GetPrimitive(ret);
        }

        private static string FindCorrelationArgument(int expected_offset, IEnumerable<Tuple<int, string>> offset_to_name)
        {
            foreach (var offset in offset_to_name)
            {
                if (offset.Item1 == expected_offset)
                {
                    return offset.Item2;
                }
                else if (offset.Item1 > expected_offset)
                {
                    break;
                }
            }
            return null;
        }

        private static void AddUnmarshalInterfaceMethod(CodeTypeDeclaration type, MarshalHelperBuilder marshal_helper)
        {
            CodeMemberMethod method = type.AddMethod(nameof(INdrStructure.Unmarshal), MemberAttributes.Final | MemberAttributes.Private);
            method.PrivateImplementationType = new CodeTypeReference(typeof(INdrStructure));
            method.AddParam(typeof(NdrUnmarshalBuffer), "u");
            method.Statements.Add(new CodeMethodInvokeExpression(new CodeMethodReferenceExpression(null, nameof(INdrStructure.Unmarshal)),
                marshal_helper.CastUnmarshal(GetVariable("u"))));
        }

        // TODO: Operations might need to be handled as int32 rather than long.
        private static CodeExpression BuildCorrelationExpression(NdrExpression expr, int current_offset,
            IEnumerable<Tuple<int, string>> offset_to_name, bool disable_correlation)
        {
            if (expr is NdrConstantExpression const_expr)
            {
                return GetPrimitive(const_expr.Value);
            }

            // Allow constant expressions even if disabled.
            if (disable_correlation)
            {
                return GetPrimitive(-1);
            }

            if (expr is NdrVariableExpression var_expr)
            {
                string var_name = FindCorrelationArgument(current_offset + var_expr.Offset, offset_to_name);
                if (var_name != null)
                {
                    return GetVariable(var_name);
                }
            }
            else if (expr is NdrOperatorExpression op_expr)
            {
                if (op_expr.Arguments.Count == 3)
                {
                    return OpTernary(BuildCorrelationExpression(op_expr.Arguments[2], current_offset, offset_to_name, false).ToBool(),
                        BuildCorrelationExpression(op_expr.Arguments[0], current_offset, offset_to_name, false),
                        BuildCorrelationExpression(op_expr.Arguments[1], current_offset, offset_to_name, false));
                }
                else if (op_expr.Arguments.Count == 2)
                {
                    switch (op_expr.Operator)
                    {
                        case NdrExpressionOperator.OP_AND:
                            return GetOpMethod(op_expr, nameof(RpcUtils.OpBitwiseAnd), current_offset, offset_to_name);
                        case NdrExpressionOperator.OP_OR:
                            return GetOpMethod(op_expr, nameof(RpcUtils.OpBitwiseOr), current_offset, offset_to_name);
                        case NdrExpressionOperator.OP_PLUS:
                            return GetOpMethod(op_expr, nameof(RpcUtils.OpPlus), current_offset, offset_to_name);
                        case NdrExpressionOperator.OP_MINUS:
                            return GetOpMethod(op_expr, nameof(RpcUtils.OpMinus), current_offset, offset_to_name);
                        case NdrExpressionOperator.OP_MOD:
                            return GetOpMethod(op_expr, nameof(RpcUtils.OpMod), current_offset, offset_to_name);
                        case NdrExpressionOperator.OP_SLASH:
                            return GetOpMethod(op_expr, nameof(RpcUtils.OpSlash), current_offset, offset_to_name);
                        case NdrExpressionOperator.OP_STAR:
                            return GetOpMethod(op_expr, nameof(RpcUtils.OpStar), current_offset, offset_to_name);
                        case NdrExpressionOperator.OP_LEFT_SHIFT:
                            return GetOpMethod(op_expr, nameof(RpcUtils.OpLeftShift), current_offset, offset_to_name);
                        case NdrExpressionOperator.OP_RIGHT_SHIFT:
                            return GetOpMethod(op_expr, nameof(RpcUtils.OpRightShift), current_offset, offset_to_name);
                        case NdrExpressionOperator.OP_XOR:
                            return GetOpMethod(op_expr, nameof(RpcUtils.OpXor), current_offset, offset_to_name);
                        case NdrExpressionOperator.OP_LOGICAL_AND:
                            return GetOpMethod(op_expr, nameof(RpcUtils.OpLogicalAnd), current_offset, offset_to_name);
                        case NdrExpressionOperator.OP_LOGICAL_OR:
                            return GetOpMethod(op_expr, nameof(RpcUtils.OpLogicalOr), current_offset, offset_to_name);
                        case NdrExpressionOperator.OP_EQUAL:
                            return GetOpMethod(op_expr, nameof(RpcUtils.OpEqual), current_offset, offset_to_name);
                        case NdrExpressionOperator.OP_NOT_EQUAL:
                            return GetOpMethod(op_expr, nameof(RpcUtils.OpNotEqual), current_offset, offset_to_name);
                        case NdrExpressionOperator.OP_LESS:
                            return GetOpMethod(op_expr, nameof(RpcUtils.OpLess), current_offset, offset_to_name);
                        case NdrExpressionOperator.OP_LESS_EQUAL:
                            return GetOpMethod(op_expr, nameof(RpcUtils.OpLessEqual), current_offset, offset_to_name);
                        case NdrExpressionOperator.OP_GREATER:
                            return GetOpMethod(op_expr, nameof(RpcUtils.OpGreater), current_offset, offset_to_name);
                        case NdrExpressionOperator.OP_GREATER_EQUAL:
                            return GetOpMethod(op_expr, nameof(RpcUtils.OpGreaterEqual), current_offset, offset_to_name);
                    }
                }
                else if (op_expr.Arguments.Count == 1)
                {
                    CodeExpression left_expr = BuildCorrelationExpression(op_expr.Arguments[0], current_offset, offset_to_name, false);

                    switch (op_expr.Operator)
                    {
                        case NdrExpressionOperator.OP_UNARY_INDIRECTION:
                            return left_expr.DeRef();
                        case NdrExpressionOperator.OP_UNARY_CAST:
                            return left_expr.Cast(GetSimpleTypeDescriptor(op_expr.Format).CodeType);
                        case NdrExpressionOperator.OP_UNARY_COMPLEMENT:
                            return GetStaticMethod(typeof(RpcUtils), nameof(RpcUtils.OpComplement), left_expr);
                        case NdrExpressionOperator.OP_UNARY_MINUS:
                            return GetStaticMethod(typeof(RpcUtils), nameof(RpcUtils.OpMinus), left_expr);
                        case NdrExpressionOperator.OP_UNARY_PLUS:
                            return GetStaticMethod(typeof(RpcUtils), nameof(RpcUtils.OpPlus), left_expr);
                    }
                }
            }

            // Can't seem to generate expression.
            return GetPrimitive(-1);
        }

        private static CodeExpression GetBinaryExpression(NdrOperatorExpression expr, CodeBinaryOperatorType op, int current_offset, IEnumerable<Tuple<int, string>> offset_to_name)
        {
            return new CodeBinaryOperatorExpression(BuildCorrelationExpression(expr.Arguments[0], current_offset, offset_to_name, false),
                op, BuildCorrelationExpression(expr.Arguments[1], current_offset, offset_to_name, false));
        }

        private static RpcTypeDescriptor GetSimpleTypeDescriptor(this NdrFormatCharacter format)
        {
            return GetSimpleTypeDescriptor(new NdrSimpleTypeReference(format), null, false);
        }

        private static CodeExpression GetOpMethod(NdrOperatorExpression op_expr, string name, int current_offset,
            IEnumerable<Tuple<int, string>> offset_to_name)
        {
            return GetStaticMethod(typeof(RpcUtils), name, BuildCorrelationExpression(op_expr.Arguments[0], current_offset, offset_to_name, false),
                                    BuildCorrelationExpression(op_expr.Arguments[1], current_offset, offset_to_name, false));
        }

        #endregion

        public static CodeNamespace AddNamespace(this CodeCompileUnit unit, string ns_name)
        {
            CodeNamespace ns = new CodeNamespace(ns_name);
            unit.Namespaces.Add(ns);
            return ns;
        }

        public static CodeNamespaceImport AddImport(this CodeNamespace ns, string import_name)
        {
            CodeNamespaceImport import = new CodeNamespaceImport(import_name);
            ns.Imports.Add(import);
            return import;
        }

        public static CodeTypeDeclaration AddType(this CodeNamespace ns, string name)
        {
            CodeTypeDeclaration type = new CodeTypeDeclaration(MakeIdentifier(name));
            ns.Types.Add(type);
            return type;
        }

        public static CodeMemberProperty AddProperty(this CodeTypeDeclaration type, string name, CodeTypeReference prop_type, MemberAttributes attributes, params CodeStatement[] get_statements)
        {
            var property = new CodeMemberProperty
            {
                Name = name,
                Type = prop_type,
                Attributes = attributes
            };
            property.GetStatements.AddRange(get_statements);
            type.Members.Add(property);
            return property;
        }

        public static CodeMemberMethod AddMethod(this CodeTypeDeclaration type, string name, MemberAttributes attributes)
        {
            CodeMemberMethod method = new CodeMemberMethod
            {
                Name = MakeIdentifier(name),
                Attributes = attributes
            };
            type.Members.Add(method);
            return method;
        }

        public static CodeMemberMethod AddMarshalMethod(this CodeTypeDeclaration type, string marshal_name, MarshalHelperBuilder marshal_helper, 
            bool non_encapsulated_union, string selector_name, CodeTypeReference selector_type)
        {
            AddMarshalInterfaceMethod(type, marshal_helper, non_encapsulated_union);
            if (non_encapsulated_union)
            {
                AddMarshalUnionInterfaceMethod(type, marshal_helper, selector_name, selector_type);
            }
            CodeMemberMethod method = type.AddMethod(nameof(INdrStructure.Marshal), MemberAttributes.Final | MemberAttributes.Private);
            method.AddParam(marshal_helper.MarshalHelperType, marshal_name);
            return method;
        }

        public static void AddConformantDimensionsMethod(this CodeTypeDeclaration type, int dimensions, MarshalHelperBuilder marshal_helper)
        {
            CodeMemberMethod method = type.AddMethod(nameof(INdrConformantStructure.GetConformantDimensions), MemberAttributes.Final | MemberAttributes.Private);
            method.PrivateImplementationType = new CodeTypeReference(typeof(INdrConformantStructure));
            method.ReturnType = typeof(int).ToRef();
            method.AddReturn(GetPrimitive(dimensions));
        }

        public static void AddAlignmentMethod(this CodeTypeDeclaration type, int alignment, MarshalHelperBuilder marshal_helper)
        {
            CodeMemberMethod method = type.AddMethod(nameof(INdrStructure.GetAlignment), MemberAttributes.Final | MemberAttributes.Private);
            method.PrivateImplementationType = new CodeTypeReference(typeof(INdrStructure));
            method.ReturnType = typeof(int).ToRef();
            method.AddReturn(GetPrimitive(alignment));
        }

        public static CodeMemberMethod AddUnmarshalMethod(this CodeTypeDeclaration type, string unmarshal_name, MarshalHelperBuilder marshal_helper)
        {
            AddUnmarshalInterfaceMethod(type, marshal_helper);
            CodeMemberMethod method = type.AddMethod(nameof(INdrStructure.Unmarshal), MemberAttributes.Final | MemberAttributes.Private);
            method.AddParam(marshal_helper.UnmarshalHelperType, unmarshal_name);
            return method;
        }

        public static void ThrowNotImplemented(this CodeMemberMethod method, string comment)
        {
            method.Statements.Add(new CodeCommentStatement(comment));
            method.AddThrow(typeof(NotImplementedException));
        }

        public static CodeConstructor AddConstructor(this CodeTypeDeclaration type, MemberAttributes attributes)
        {
            var cons = new CodeConstructor
            {
                Attributes = attributes
            };
            type.Members.Add(cons);
            return cons;
        }

        public static CodeParameterDeclarationExpression AddParam(this CodeMemberMethod method, Type type, string name)
        {
            var param = new CodeParameterDeclarationExpression(type, MakeIdentifier(name));
            method.Parameters.Add(param);
            return param;
        }

        public static CodeParameterDeclarationExpression AddParam(this CodeMemberMethod method, CodeTypeReference type, string name)
        {
            var param = new CodeParameterDeclarationExpression(type, MakeIdentifier(name));
            method.Parameters.Add(param);
            return param;
        }

        public static CodeMemberField AddField(this CodeTypeDeclaration type, CodeTypeReference builtin_type, string name, MemberAttributes attributes)
        {
            var field = new CodeMemberField(builtin_type, name)
            {
                Attributes = attributes
            };
            type.Members.Add(field);
            return field;
        }

        public static CodeFieldReferenceExpression GetFieldReference(this CodeExpression target, string name)
        {
            return new CodeFieldReferenceExpression(target, name);
        }

        public static CodeMethodReturnStatement AddReturn(this CodeMemberMethod method, CodeExpression return_expr)
        {
            CodeMethodReturnStatement ret = new CodeMethodReturnStatement(return_expr);
            method.Statements.Add(ret);
            return ret;
        }

        public static void AddDefaultConstructorMethod(this CodeTypeDeclaration type, string name, MemberAttributes attributes, RpcTypeDescriptor complex_type, Dictionary<string, CodeExpression> initialize_expr)
        {
            CodeMemberMethod method = type.AddMethod(name, attributes);
            method.ReturnType = complex_type.CodeType;
            CodeExpression return_value = new CodeObjectCreateExpression(complex_type.CodeType);
            if (initialize_expr.Count > 0)
            {
                method.Statements.Add(new CodeVariableDeclarationStatement(complex_type.CodeType, "ret", return_value));
                return_value = GetVariable("ret");
                method.Statements.AddRange(initialize_expr.Select(p => new CodeAssignStatement(return_value.GetFieldReference(p.Key), p.Value)).ToArray());
            }
            method.AddReturn(return_value);
        }

        
        public static void AddComment(this CodeCommentStatementCollection comments, string text)
        {
            comments.Add(new CodeCommentStatement(text));
        }

        public static void AddComment(this CodeNamespace ns, string text)
        {
            ns.Comments.AddComment(text);
        }

        public static void AddConstructorMethod(this CodeTypeDeclaration type, string name, 
            RpcTypeDescriptor complex_type, IEnumerable<Tuple<CodeTypeReference, string, bool>> parameters)
        {
            if (!parameters.Any())
            {
                return;
            }

            CodeMemberMethod method = type.AddMethod(name, MemberAttributes.Public | MemberAttributes.Final);
            method.ReturnType = complex_type.CodeType;
            method.Statements.Add(new CodeVariableDeclarationStatement(complex_type.CodeType, "ret", new CodeObjectCreateExpression(complex_type.CodeType)));
            CodeExpression return_value = GetVariable("ret");
            method.AddAssignmentStatements(return_value, parameters.Where(t => !t.Item3));
            method.AddReturn(return_value);
        }

        public static void AddConstructorMethod(this CodeTypeDeclaration type, RpcTypeDescriptor complex_type, IEnumerable<Tuple<CodeTypeReference, string, bool>> parameters)
        {
            if (!parameters.Any())
            {
                return;
            }

            CodeMemberMethod method = type.AddConstructor(MemberAttributes.Public | MemberAttributes.Final);
            method.AddAssignmentStatements(new CodeThisReferenceExpression(), parameters);
        }

        public static void AddArrayConstructorMethod(this CodeTypeDeclaration type, string name, RpcTypeDescriptor complex_type)
        {
            CodeMemberMethod method = type.AddMethod(name, MemberAttributes.Public | MemberAttributes.Final);
            method.AddParam(new CodeTypeReference(typeof(int)), "size");
            method.ReturnType = complex_type.GetArrayType();
            method.AddReturn(new CodeArrayCreateExpression(complex_type.CodeType, GetVariable("size")));
        }

        public static CodeExpression GetVariable(string var_name, bool null_check)
        {
            CodeExpression ret;
            if (var_name == null)
            {
                ret = new CodeThisReferenceExpression();
            }
            else
            {
                ret = new CodeVariableReferenceExpression(MakeIdentifier(var_name));
            }

            if (null_check)
            {
                return AddNullCheck(ret, var_name);
            }

            return ret;
        }

        public static CodeExpression GetVariable(string var_name)
        {
            return GetVariable(var_name, false);
        }

        public static void AddMarshalCall(this CodeMemberMethod method, RpcTypeDescriptor descriptor, string marshal_name, string var_name, bool add_write_referent,
            bool null_check, CodeExpression case_selector, string union_selector, string done_label, params RpcMarshalArgument[] additional_args)
        {
            List<CodeExpression> args = new List<CodeExpression>
            {
                GetVariable(var_name, null_check)
            };

            CodeMethodReferenceExpression marshal_method = descriptor.GetMarshalMethod(GetVariable(marshal_name));
            if (add_write_referent)
            {
                List<CodeTypeReference> marshal_args = new List<CodeTypeReference>();
                marshal_args.Add(descriptor.CodeType);
                marshal_args.AddRange(additional_args.Select(a => a.CodeType));
                var create_delegate = new CodeDelegateCreateExpression(CreateActionType(marshal_args.ToArray()),
                    GetVariable(marshal_name), descriptor.MarshalMethod);
                args.Add(create_delegate);
                marshal_method = new CodeMethodReferenceExpression(GetVariable(marshal_name), nameof(NdrMarshalBuffer.WriteReferent));
            }

            args.AddRange(additional_args.Select(r => r.Expression));
            CodeMethodInvokeExpression invoke = new CodeMethodInvokeExpression(marshal_method, args.ToArray());

            if (case_selector != null)
            {
                method.Statements.Add(new CodeConditionStatement(new CodeBinaryOperatorExpression(GetVariable(union_selector), 
                    CodeBinaryOperatorType.ValueEquality, case_selector),
                    new CodeExpressionStatement(invoke), new CodeGotoStatement(done_label)));
            }
            else
            {
                method.Statements.Add(invoke);
            }
        }

        public static CodeTypeReference CreateActionType(params CodeTypeReference[] args)
        {
            CodeTypeReference delegate_type = null;
            switch(args.Length)
            {
                case 0:
                    delegate_type = new CodeTypeReference(typeof(Action));
                    break;
                case 1:
                    delegate_type = new CodeTypeReference(typeof(Action<>));
                    break;
                case 2:
                    delegate_type = new CodeTypeReference(typeof(Action<,>));
                    break;
                case 3:
                    delegate_type = new CodeTypeReference(typeof(Action<,,>));
                    break;
                default:
                    throw new ArgumentException("Too many delegate arguments");
            }

            delegate_type.TypeArguments.AddRange(args);
            return delegate_type;
        }

        public static CodeTypeReference CreateFuncType(CodeTypeReference ret, params CodeTypeReference[] args)
        {
            CodeTypeReference delegate_type = null;
            switch (args.Length)
            {
                case 0:
                    delegate_type = new CodeTypeReference(typeof(Func<>));
                    break;
                case 1:
                    delegate_type = new CodeTypeReference(typeof(Func<,>));
                    break;
                case 2:
                    delegate_type = new CodeTypeReference(typeof(Func<,,>));
                    break;
                case 3:
                    delegate_type = new CodeTypeReference(typeof(Func<,,,>));
                    break;
                default:
                    throw new ArgumentException("Too many delegate arguments");
            }

            delegate_type.TypeArguments.AddRange(args);
            delegate_type.TypeArguments.Add(ret);
            return delegate_type;
        }

        public static CodeExpression CreateDelegate(CodeTypeReference delegate_type, CodeExpression target, string name)
        {
            return new CodeDelegateCreateExpression(delegate_type, target, name);
        }

        public static void AddDeferredMarshalCall(this CodeMemberMethod method, RpcTypeDescriptor descriptor, string marshal_name, string var_name,
            CodeExpression case_selector, string union_selector, string done_label, params RpcMarshalArgument[] additional_args)
        {
            List<CodeExpression> args = new List<CodeExpression>
            {
                GetVariable(var_name)
            };

            List<CodeTypeReference> marshal_args = new List<CodeTypeReference>();
            marshal_args.Add(descriptor.CodeType);
            marshal_args.AddRange(additional_args.Select(a => a.CodeType));

            string method_name;
            method_name = nameof(NdrMarshalBuffer.WriteEmbeddedPointer);
            var create_delegate = new CodeDelegateCreateExpression(CreateActionType(marshal_args.ToArray()),
                GetVariable(marshal_name), descriptor.MarshalMethod);

            args.Add(create_delegate);
            args.AddRange(additional_args.Select(r => r.Expression));
            CodeMethodReferenceExpression write_pointer = new CodeMethodReferenceExpression(GetVariable(marshal_name), method_name, marshal_args.ToArray());
            CodeMethodInvokeExpression invoke = new CodeMethodInvokeExpression(write_pointer, args.ToArray());
            if (case_selector != null)
            {
                method.Statements.Add(new CodeConditionStatement(new CodeBinaryOperatorExpression(GetVariable(union_selector), 
                    CodeBinaryOperatorType.ValueEquality, case_selector),
                    new CodeExpressionStatement(invoke), new CodeGotoStatement(done_label)));
            }
            else
            {
                method.Statements.Add(invoke);
            }
        }

        public static void AddUnmarshalCall(this CodeMemberMethod method, RpcTypeDescriptor descriptor, string unmarshal_name,
            string var_name, CodeExpression case_selector, string union_selector, string done_label, params CodeExpression[] additional_args)
        {
            List<CodeExpression> args = new List<CodeExpression>();
            args.AddRange(additional_args);

            CodeStatement assign = new CodeAssignStatement(GetVariable(var_name), descriptor.GetUnmarshalMethodInvoke(unmarshal_name, args));
            if (case_selector != null)
            {
                assign = new CodeConditionStatement(new CodeBinaryOperatorExpression(GetVariable(union_selector),
                    CodeBinaryOperatorType.ValueEquality, case_selector),
                    assign, new CodeGotoStatement(done_label));
            }
            method.Statements.Add(assign);
        }

        public static CodePrimitiveExpression GetPrimitive(object obj)
        {
            return new CodePrimitiveExpression(obj);
        }

        public static void AddDeferredEmbeddedUnmarshalCall(this CodeMemberMethod method, RpcTypeDescriptor descriptor, string unmarshal_name, string var_name,
            CodeExpression case_selector, string union_selector, string done_label, params RpcMarshalArgument[] additional_args)
        {
            List<CodeExpression> args = new List<CodeExpression>();
            List<CodeTypeReference> marshal_args = new List<CodeTypeReference>();
            marshal_args.Add(descriptor.CodeType);
            marshal_args.AddRange(additional_args.Select(a => a.CodeType));

            var create_delegate = new CodeDelegateCreateExpression(CreateFuncType(descriptor.CodeType, marshal_args.Skip(1).ToArray()),
                descriptor.GetUnmarshalTarget(unmarshal_name), descriptor.UnmarshalMethod);
            args.Add(create_delegate);
            args.Add(GetPrimitive(descriptor.Pointer && descriptor.PointerType == RpcPointerType.Full));
            args.AddRange(additional_args.Select(r => r.Expression));
            CodeMethodReferenceExpression read_pointer = new CodeMethodReferenceExpression(GetVariable(unmarshal_name), 
                nameof(NdrUnmarshalBuffer.ReadEmbeddedPointer), marshal_args.ToArray());
            CodeMethodInvokeExpression invoke = new CodeMethodInvokeExpression(read_pointer, args.ToArray());
            CodeStatement assign = new CodeAssignStatement(GetVariable(var_name), invoke);

            if (case_selector != null)
            {
                assign = new CodeConditionStatement(new CodeBinaryOperatorExpression(GetVariable(union_selector),
                    CodeBinaryOperatorType.ValueEquality, case_selector),
                    assign, new CodeGotoStatement(done_label));
            }

            method.Statements.Add(assign);
        }

        public static void AddPointerUnmarshalCall(this CodeMemberMethod method, RpcTypeDescriptor descriptor, string unmarshal_name, string var_name)
        {
            List<CodeExpression> args = new List<CodeExpression>();
            List<CodeTypeReference> marshal_args = new List<CodeTypeReference>();
            marshal_args.Add(descriptor.CodeType);

            var create_delegate = new CodeDelegateCreateExpression(CreateFuncType(descriptor.CodeType, marshal_args.Skip(1).ToArray()),
                descriptor.GetUnmarshalTarget(unmarshal_name), descriptor.UnmarshalMethod);
            args.Add(create_delegate);
            args.Add(GetPrimitive(descriptor.Pointer && descriptor.PointerType == RpcPointerType.Full));
            CodeMethodReferenceExpression read_pointer = new CodeMethodReferenceExpression(GetVariable(unmarshal_name),
                descriptor.ValueType ? nameof(NdrUnmarshalBuffer.ReadReferentValue) : nameof(NdrUnmarshalBuffer.ReadReferent), marshal_args.ToArray());
            CodeMethodInvokeExpression invoke = new CodeMethodInvokeExpression(read_pointer, args.ToArray());
            CodeStatement assign = new CodeAssignStatement(GetVariable(var_name), invoke);
            method.Statements.Add(assign);
        }

        public static void AddUnmarshalReturn(this CodeMemberMethod method, RpcTypeDescriptor descriptor, string unmarshal_name, params RpcMarshalArgument[] additional_args)
        {
            if (descriptor.BuiltinType == typeof(void))
            {
                return;
            }
            List<CodeExpression> args = new List<CodeExpression>();
            args.AddRange(additional_args.Select(r => r.Expression));
            CodeMethodReturnStatement ret = new CodeMethodReturnStatement(descriptor.GetUnmarshalMethodInvoke(unmarshal_name, args));
            method.Statements.Add(ret);
        }

        public static CodeExpression AddNullCheck(this CodeExpression var_expr, string var_name)
        {
            return GetStaticMethod(typeof(RpcUtils), nameof(RpcUtils.CheckNull), var_expr, GetPrimitive(var_name));
        }

        public static FieldDirection GetDirection(this NdrProcedureParameter p)
        {
            bool is_in = p.Attributes.HasFlag(NdrParamAttributes.IsIn);
            bool is_out = p.Attributes.HasFlag(NdrParamAttributes.IsOut);

            if (is_in && is_out)
            {
                return FieldDirection.Ref;
            }
            else if (is_out)
            {
                return FieldDirection.Out;
            }
            return FieldDirection.In;
        }

        public static void CreateMarshalObject(this CodeMemberMethod method, string name, MarshalHelperBuilder marshal_helper)
        {
            method.Statements.Add(new CodeVariableDeclarationStatement(marshal_helper.MarshalHelperType, name, new CodeObjectCreateExpression(marshal_helper.MarshalHelperType)));
        }

        public static void CreateSendReceive(this CodeTypeDeclaration type, MarshalHelperBuilder marshal_helper)
        {
            var method = type.AddMethod("SendReceive", MemberAttributes.Private | MemberAttributes.Final);
            method.AddParam(typeof(int), "p");
            method.AddParam(marshal_helper.MarshalHelperType, "m");
            method.ReturnType = marshal_helper.UnmarshalHelperType;

            CodeExpression call_sendrecv = new CodeMethodInvokeExpression(null, "SendReceive",
                GetVariable("p"),
                new CodePropertyReferenceExpression(GetVariable("m"), nameof(NdrMarshalBuffer.DataRepresentation)),
                new CodeMethodInvokeExpression(GetVariable("m"), nameof(NdrMarshalBuffer.ToArray)),
                new CodePropertyReferenceExpression(GetVariable("m"), nameof(NdrMarshalBuffer.Handles)));
            call_sendrecv = new CodeObjectCreateExpression(marshal_helper.UnmarshalHelperType, call_sendrecv);
            method.AddReturn(call_sendrecv);
        }

        public static void SendReceive(this CodeMemberMethod method, string marshal_name, string unmarshal_name, int proc_num, MarshalHelperBuilder marshal_helper)
        {
            CodeExpression call_sendrecv = new CodeMethodInvokeExpression(null, "SendReceive",
                GetPrimitive(proc_num),
                GetVariable(marshal_name));
            CodeVariableDeclarationStatement unmarshal = new CodeVariableDeclarationStatement(marshal_helper.UnmarshalHelperType, unmarshal_name, call_sendrecv);
            method.Statements.Add(unmarshal);
        }

        public static void AddStartRegion(this CodeTypeDeclaration type, string text)
        {
            type.StartDirectives.Add(new CodeRegionDirective(CodeRegionMode.Start, text));
        }

        public static void AddEndRegion(this CodeTypeDeclaration type)
        {
            type.EndDirectives.Add(new CodeRegionDirective(CodeRegionMode.End, string.Empty));
        }

        public static string MakeIdentifier(string id)
        {
            id = _identifier_regex.Replace(id, "_");
            if (!char.IsLetter(id[0]) && id[0] != '_')
            {
                id = "_" + id;
            }

            return id;
        }

        public static Type GetSystemHandleType(this NdrSystemHandleTypeReference type)
        {
            switch (type.Resource)
            {
                case NdrSystemHandleResource.File:
                case NdrSystemHandleResource.Pipe:
                case NdrSystemHandleResource.Socket:
                    return typeof(NtFile);
                case NdrSystemHandleResource.Semaphore:
                    return typeof(NtSemaphore);
                case NdrSystemHandleResource.RegKey:
                    return typeof(NtKey);
                case NdrSystemHandleResource.Event:
                    return typeof(NtEvent);
                case NdrSystemHandleResource.Job:
                    return typeof(NtJob);
                case NdrSystemHandleResource.Mutex:
                    return typeof(NtMutant);
                case NdrSystemHandleResource.Process:
                    return typeof(NtProcess);
                case NdrSystemHandleResource.Section:
                    return typeof(NtSection);
                case NdrSystemHandleResource.Thread:
                    return typeof(NtThread);
                case NdrSystemHandleResource.Token:
                    return typeof(NtToken);
                default:
                    return typeof(NtObject);
            }
        }

        public static bool ValidateCorrelation(this NdrCorrelationDescriptor correlation)
        {
            if (!correlation.IsConstant && !correlation.IsNormal 
                && !correlation.IsTopLevel && !correlation.IsPointer)
            {
                return false;
            }

            switch (correlation.Operator)
            {
                case NdrFormatCharacter.FC_ADD_1:
                case NdrFormatCharacter.FC_DIV_2:
                case NdrFormatCharacter.FC_MULT_2:
                case NdrFormatCharacter.FC_SUB_1:
                case NdrFormatCharacter.FC_ZERO:
                case NdrFormatCharacter.FC_DEREFERENCE:
                    break;
                case NdrFormatCharacter.FC_EXPR:
                    return correlation.Expression.IsValid;
                default:
                    return false;
            }

            return true;
        }

        public static RpcTypeDescriptor GetSimpleTypeDescriptor(this NdrSimpleTypeReference simple_type, MarshalHelperBuilder marshal_helper, bool unsigned_char)
        {
            NdrFormatCharacter format = simple_type.Format;
            if (unsigned_char && format == NdrFormatCharacter.FC_CHAR)
            {
                format = NdrFormatCharacter.FC_BYTE;
            }

            switch (format)
            {
                case NdrFormatCharacter.FC_BYTE:
                case NdrFormatCharacter.FC_USMALL:
                    return new RpcTypeDescriptor(typeof(byte), nameof(NdrUnmarshalBuffer.ReadByte), nameof(NdrMarshalBuffer.WriteByte), simple_type);
                case NdrFormatCharacter.FC_SMALL:
                case NdrFormatCharacter.FC_CHAR:
                    return new RpcTypeDescriptor(typeof(sbyte), nameof(NdrUnmarshalBuffer.ReadSByte), nameof(NdrMarshalBuffer.WriteSByte), simple_type);
                case NdrFormatCharacter.FC_WCHAR:
                    return new RpcTypeDescriptor(typeof(char), nameof(NdrUnmarshalBuffer.ReadChar), nameof(NdrMarshalBuffer.WriteChar), simple_type);
                case NdrFormatCharacter.FC_SHORT:
                    return new RpcTypeDescriptor(typeof(short), nameof(NdrUnmarshalBuffer.ReadInt16), nameof(NdrMarshalBuffer.WriteInt16), simple_type);
                case NdrFormatCharacter.FC_ENUM16:
                    return new RpcTypeDescriptor(typeof(NdrEnum16), nameof(NdrUnmarshalBuffer.ReadEnum16), nameof(NdrMarshalBuffer.WriteEnum16), simple_type);
                case NdrFormatCharacter.FC_USHORT:
                    return new RpcTypeDescriptor(typeof(ushort), nameof(NdrUnmarshalBuffer.ReadUInt16), nameof(NdrMarshalBuffer.WriteUInt16), simple_type);
                case NdrFormatCharacter.FC_LONG:
                case NdrFormatCharacter.FC_ENUM32:
                    return new RpcTypeDescriptor(typeof(int), nameof(NdrUnmarshalBuffer.ReadInt32), nameof(NdrMarshalBuffer.WriteInt32), simple_type);
                case NdrFormatCharacter.FC_ULONG:
                case NdrFormatCharacter.FC_ERROR_STATUS_T:
                    return new RpcTypeDescriptor(typeof(uint), nameof(NdrUnmarshalBuffer.ReadUInt32), nameof(NdrMarshalBuffer.WriteUInt32), simple_type);
                case NdrFormatCharacter.FC_FLOAT:
                    return new RpcTypeDescriptor(typeof(float), nameof(NdrUnmarshalBuffer.ReadFloat), nameof(NdrMarshalBuffer.WriteFloat), simple_type);
                case NdrFormatCharacter.FC_HYPER:
                    return new RpcTypeDescriptor(typeof(long), nameof(NdrUnmarshalBuffer.ReadInt64), nameof(NdrMarshalBuffer.WriteInt64), simple_type);
                case NdrFormatCharacter.FC_DOUBLE:
                    return new RpcTypeDescriptor(typeof(double), nameof(NdrUnmarshalBuffer.ReadDouble), nameof(NdrMarshalBuffer.WriteDouble), simple_type);
                case NdrFormatCharacter.FC_INT3264:
                    return new RpcTypeDescriptor(typeof(NdrInt3264), nameof(NdrUnmarshalBuffer.ReadInt3264), nameof(NdrMarshalBuffer.WriteInt3264), simple_type);
                case NdrFormatCharacter.FC_UINT3264:
                    return new RpcTypeDescriptor(typeof(NdrUInt3264), nameof(NdrUnmarshalBuffer.ReadUInt3264), nameof(NdrMarshalBuffer.WriteUInt3264), simple_type);
                case NdrFormatCharacter.FC_C_WSTRING:
                    return new RpcTypeDescriptor(typeof(string), nameof(NdrUnmarshalBuffer.ReadConformantVaryingString), nameof(NdrMarshalBuffer.WriteTerminatedString), simple_type);
                case NdrFormatCharacter.FC_C_CSTRING:
                    return new RpcTypeDescriptor(typeof(string), nameof(NdrUnmarshalBuffer.ReadConformantVaryingAnsiString), nameof(NdrMarshalBuffer.WriteTerminatedAnsiString), simple_type);
                case NdrFormatCharacter.FC_ZERO:
                    return new RpcTypeDescriptor(typeof(NdrEmpty), nameof(NdrUnmarshalBuffer.ReadEmpty), nameof(NdrMarshalBuffer.WriteEmpty), simple_type);
            }
            return null;
        }

        public static RpcMarshalArgument CalculateCorrelationArgument(this NdrCorrelationDescriptor correlation,
            int current_offset, IEnumerable<Tuple<int, string>> offset_to_name, bool disable_correlation)
        {
            if (correlation.IsConstant)
            {
                return RpcMarshalArgument.CreateFromPrimitive((long)correlation.Offset);
            }

            if (correlation.IsTopLevel || correlation.IsPointer)
            {
                current_offset = 0;
            }

            if (correlation.Expression.IsValid)
            {
                return new RpcMarshalArgument(BuildCorrelationExpression(correlation.Expression, 
                    current_offset, offset_to_name, disable_correlation), typeof(long).ToRef());
            }

            if (disable_correlation)
            {
                return RpcMarshalArgument.CreateFromPrimitive(-1L);
            }

            var offset = FindCorrelationArgument(current_offset + correlation.Offset, offset_to_name);
            if (offset != null)
            {
                CodeExpression expr = GetVariable(offset);
                CodeExpression right_expr = null;
                CodeBinaryOperatorType operator_type = CodeBinaryOperatorType.Add;
                switch (correlation.Operator)
                {
                    case NdrFormatCharacter.FC_ADD_1:
                        right_expr = GetPrimitive(1);
                        operator_type = CodeBinaryOperatorType.Add;
                        break;
                    case NdrFormatCharacter.FC_DIV_2:
                        right_expr = GetPrimitive(2);
                        operator_type = CodeBinaryOperatorType.Divide;
                        break;
                    case NdrFormatCharacter.FC_MULT_2:
                        right_expr = GetPrimitive(2);
                        operator_type = CodeBinaryOperatorType.Multiply;
                        break;
                    case NdrFormatCharacter.FC_SUB_1:
                        right_expr = GetPrimitive(2);
                        operator_type = CodeBinaryOperatorType.Multiply;
                        break;
                    case NdrFormatCharacter.FC_DEREFERENCE:
                        expr = expr.DeRef();
                        break;
                }

                if (right_expr != null)
                {
                    expr = new CodeBinaryOperatorExpression(expr, operator_type, right_expr);
                }
                return new RpcMarshalArgument(expr, new CodeTypeReference(typeof(long)));
            }

            // We failed to find the base name, return -1 as a default.
            return RpcMarshalArgument.CreateFromPrimitive(-1L);
        }

        public static CodeTypeReference ToRef(this Type type)
        {
            return new CodeTypeReference(type);
        }
        public static CodeTypeReference ToRef(this Type type, params CodeTypeReference[] generic_types)
        {
            var ret = new CodeTypeReference(type);
            ret.TypeArguments.AddRange(generic_types);
            return ret;
        }

        public static CodeTypeReference ToRefArray(this CodeTypeReference type)
        {
            return new CodeTypeReference(type, type.ArrayRank + 1);
        }

        public static CodeTypeReference ToBaseRef(this CodeTypeReference type)
        {
            return type.ArrayElementType ?? type;
        }

        public static bool IsNonEncapsulatedUnion(this NdrComplexTypeReference complex_type)
        {
            if (complex_type is NdrUnionTypeReference union_type)
            {
                return union_type.NonEncapsulated;
            }
            return false;
        }

        public static bool IsUnion(this NdrComplexTypeReference complex_type)
        {
            return complex_type is NdrUnionTypeReference;
        }

        public static bool IsStruct(this NdrComplexTypeReference complex_type)
        {
            return complex_type is NdrBaseStructureTypeReference;
        }

        public static bool IsConformantStruct(this NdrComplexTypeReference complex_type)
        {
            if (complex_type is NdrBaseStructureTypeReference struct_type)
            {
                return struct_type.Conformant;
            }
            return false;
        }

        public static int GetConformantDimensions(this NdrComplexTypeReference complex_type)
        {
            if (complex_type.IsConformantStruct())
            {
                return 1;
            }
            return 0;
        }

        public static int GetAlignment(this NdrComplexTypeReference complex_type)
        {
            if (complex_type is NdrBaseStructureTypeReference struct_type)
            {
                return struct_type.Alignment + 1;
            }
            else if (complex_type is NdrUnionTypeReference union_type)
            {
                return union_type.Arms.Alignment + 1;
            }
            return 0;
        }

        public static List<ComplexTypeMember> GetMembers(this NdrComplexTypeReference complex_type, string selector_name)
        {
            List<ComplexTypeMember> members = new List<ComplexTypeMember>();
            if (complex_type is NdrBaseStructureTypeReference struct_type)
            {
                members.AddRange(struct_type.Members.Select(m => new ComplexTypeMember(m.MemberType, m.Offset, m.Name, null, false, false)).ToList());
            }
            else if (complex_type is NdrUnionTypeReference union_type)
            {
                var selector_type = new NdrSimpleTypeReference(union_type.SwitchType);
                int base_offset = selector_type.GetSize();
                members.Add(new ComplexTypeMember(selector_type, 0, selector_name, null, false, union_type.NonEncapsulated));
                if (!union_type.NonEncapsulated)
                {
                    base_offset = union_type.SwitchIncrement;
                }

                members.AddRange(union_type.Arms.Arms.Select(a => new ComplexTypeMember(a.ArmType, base_offset, $"Arm_{FormatCaseLabel(a)}", a.GetArmCase(selector_type), false, false)));
                if (union_type.Arms.DefaultArm != null)
                {
                    members.Add(new ComplexTypeMember(union_type.Arms.DefaultArm, base_offset, "Arm_Default", null, true, false));
                }
            }
            return members;
        }

        public static NdrSimpleTypeReference GetSelectorType(this NdrComplexTypeReference complex_type)
        {
            if (complex_type is NdrUnionTypeReference union_type)
            {
                return new NdrSimpleTypeReference(union_type.SwitchType);
            }
            return null;
        }

        public static NdrCorrelationDescriptor GetUnionCorrelation(this NdrComplexTypeReference complex_type)
        {
            if (complex_type is NdrUnionTypeReference union_type && union_type.NonEncapsulated && union_type.Correlation.ValidateCorrelation())
            {
                return union_type.Correlation;
            }
            return null;
        }

        public static void AddThrow(this CodeMemberMethod method, Type exception_type, params object[] args)
        {
            method.Statements.Add(new CodeThrowExceptionStatement(new CodeObjectCreateExpression(exception_type.ToRef(), args.Select(o => GetPrimitive(o)).ToArray())));
        }

        public static CodeMethodInvokeExpression GetStaticMethod(Type type, string name, params CodeExpression[] ps)
        {
            return new CodeMethodInvokeExpression(new CodeTypeReferenceExpression(type), name, ps);
        }

        public static CodeExpression DeRef(this CodeExpression expr)
        {
            return GetStaticMethod(typeof(RpcUtils), nameof(RpcUtils.DeRef), expr);
        }

        public static void AddBreakpoint(this CodeMemberMethod method)
        {
            method.Statements.Add(GetStaticMethod(typeof(System.Diagnostics.Debugger), nameof(System.Diagnostics.Debugger.Break)));
        }

        public static CodeExpression Cast(this CodeExpression expr, CodeTypeReference type)
        {
            return new CodeCastExpression(type, expr);
        }

        public static CodeExpression OpTernary(CodeExpression condition_expr, CodeExpression true_expr, CodeExpression false_expr)
        {
            return GetStaticMethod(typeof(RpcUtils), nameof(RpcUtils.OpTernary), condition_expr, true_expr, false_expr);
        }

        public static CodeExpression ToBool(this CodeExpression expr)
        {
            return GetStaticMethod(typeof(RpcUtils), nameof(RpcUtils.ToBool), expr);
        }
    }
}
