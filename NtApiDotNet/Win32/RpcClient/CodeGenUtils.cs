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
using System;
using System.CodeDom;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace NtApiDotNet.Win32.RpcClient
{
    internal static class CodeGenUtils
    {
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
            var property = new CodeMemberProperty();
            property.Name = name;
            property.Type = prop_type;
            property.Attributes = attributes;
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

        private static void AddMarshalInterfaceMethod(CodeTypeDeclaration type, MarshalHelperBuilder marshal_helper)
        {
            CodeMemberMethod method = type.AddMethod("Marshal", MemberAttributes.Final | MemberAttributes.Private);
            method.PrivateImplementationType = new CodeTypeReference(typeof(INdrStructure));
            method.AddParam(typeof(NdrMarshalBuffer), "m");
            method.Statements.Add(new CodeMethodInvokeExpression(new CodeMethodReferenceExpression(null, "Marshal"),
                marshal_helper.CastMarshal(GetVariable("m"))));
        }

        public static CodeMemberMethod AddMarshalMethod(this CodeTypeDeclaration type, string marshal_name, MarshalHelperBuilder marshal_helper)
        {
            AddMarshalInterfaceMethod(type, marshal_helper);

            CodeMemberMethod method = type.AddMethod("Marshal", MemberAttributes.Final | MemberAttributes.Private);
            method.AddParam(marshal_helper.MarshalHelperType, marshal_name);
            return method;
        }

        public static void AddAlign(this CodeMemberMethod method, string marshal_name, int align)
        {
            method.Statements.Add(new CodeMethodInvokeExpression(GetVariable(marshal_name), "Align", GetPrimitive(align)));
        }

        private static void AddUnmarshalInterfaceMethod(CodeTypeDeclaration type, MarshalHelperBuilder marshal_helper)
        {
            CodeMemberMethod method = type.AddMethod("Unmarshal", MemberAttributes.Final | MemberAttributes.Private);
            method.PrivateImplementationType = new CodeTypeReference(typeof(INdrStructure));
            method.AddParam(typeof(NdrUnmarshalBuffer), "u");
            method.Statements.Add(new CodeMethodInvokeExpression(new CodeMethodReferenceExpression(null, "Unmarshal"),
                marshal_helper.CastUnmarshal(GetVariable("u"))));
        }

        public static CodeMemberMethod AddUnmarshalMethod(this CodeTypeDeclaration type, string unmarshal_name, MarshalHelperBuilder marshal_helper)
        {
            AddUnmarshalInterfaceMethod(type, marshal_helper);
            CodeMemberMethod method = type.AddMethod("Unmarshal", MemberAttributes.Final | MemberAttributes.Private);
            method.AddParam(marshal_helper.UnmarshalHelperType, unmarshal_name);
            return method;
        }

        public static void ThrowNotImplemented(this CodeMemberMethod method, string comment)
        {
            method.Statements.Add(new CodeCommentStatement(comment));
            method.Statements.Add(new CodeThrowExceptionStatement(new CodeObjectCreateExpression(typeof(NotImplementedException))));
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

        public static CodeMemberField AddField(this CodeTypeDeclaration type, Type builtin_type, string name, MemberAttributes attributes)
        {
            return AddField(type, new CodeTypeReference(builtin_type), name, attributes);
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

        private static void AddAssignmentStatements(this CodeMemberMethod method, CodeExpression target, IEnumerable<Tuple<CodeTypeReference, string>> parameters)
        {
            foreach (var p in parameters)
            {
                method.AddParam(p.Item1, p.Item2);
                method.Statements.Add(new CodeAssignStatement(target.GetFieldReference(p.Item2), GetVariable(p.Item2)));
            }
        }

        public static void AddComment(this CodeCommentStatementCollection comments, string text)
        {
            comments.Add(new CodeCommentStatement(text));
        }

        public static void AddComment(this CodeNamespace ns, string text)
        {
            ns.Comments.AddComment(text);
        }

        public static void AddConstructorMethod(this CodeTypeDeclaration type, string name, RpcTypeDescriptor complex_type, IEnumerable<Tuple<CodeTypeReference, string>> parameters)
        {
            if (!parameters.Any())
            {
                return;
            }

            CodeMemberMethod method = type.AddMethod(name, MemberAttributes.Public | MemberAttributes.Final);
            method.ReturnType = complex_type.CodeType;
            method.Statements.Add(new CodeVariableDeclarationStatement(complex_type.CodeType, "ret", new CodeObjectCreateExpression(complex_type.CodeType)));
            CodeExpression return_value = GetVariable("ret");
            method.AddAssignmentStatements(return_value, parameters);
            method.AddReturn(return_value);
        }

        public static void AddConstructorMethod(this CodeTypeDeclaration type, RpcTypeDescriptor complex_type, IEnumerable<Tuple<CodeTypeReference, string>> parameters)
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

        public static CodeExpression GetVariable(string var_name)
        {
            if (var_name == null)
            {
                return new CodeThisReferenceExpression();
            }
            return new CodeVariableReferenceExpression(MakeIdentifier(var_name));
        }

        public static void AddMarshalCall(this CodeMemberMethod method, RpcTypeDescriptor descriptor, string marshal_name, string var_name, params RpcMarshalArgument[] additional_args)
        {
            List<CodeExpression> args = new List<CodeExpression>
            {
                GetVariable(var_name)
            };
            args.AddRange(additional_args.Select(r => r.Expression));
            CodeMethodInvokeExpression invoke = new CodeMethodInvokeExpression(descriptor.GetMarshalMethod(GetVariable(marshal_name)), args.ToArray());
            method.Statements.Add(invoke);
        }

        public static void AddFlushDeferredWrites(this CodeMemberMethod method, string marshal_name)
        {
            method.Statements.Add(new CodeMethodInvokeExpression(GetVariable(marshal_name), "FlushDeferredWrites"));
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

        public static void AddDeferredMarshalCall(this CodeMemberMethod method, RpcTypeDescriptor descriptor, string marshal_name, string var_name, params RpcMarshalArgument[] additional_args)
        {
            List<CodeExpression> args = new List<CodeExpression>
            {
                GetVariable(var_name)
            };

            List<CodeTypeReference> marshal_args = new List<CodeTypeReference>();
            marshal_args.Add(descriptor.CodeType);
            marshal_args.AddRange(additional_args.Select(a => a.CodeType));

            string method_name;
            method_name = "WriteEmbeddedPointer";
            var create_delegate = new CodeDelegateCreateExpression(CreateActionType(marshal_args.ToArray()),
                GetVariable(marshal_name), descriptor.MarshalMethod);

            args.Add(create_delegate);
            args.AddRange(additional_args.Select(r => r.Expression));
            CodeMethodReferenceExpression write_pointer = new CodeMethodReferenceExpression(GetVariable(marshal_name), method_name, marshal_args.ToArray());
            CodeMethodInvokeExpression invoke = new CodeMethodInvokeExpression(write_pointer, args.ToArray());
            method.Statements.Add(invoke);
        }

        public static void AddUnmarshalCall(this CodeMemberMethod method, RpcTypeDescriptor descriptor, string unmarshal_name, string var_name, params CodeExpression[] additional_args)
        {
            List<CodeExpression> args = new List<CodeExpression>();
            args.AddRange(additional_args);

            CodeAssignStatement assign = new CodeAssignStatement(GetVariable(var_name), descriptor.GetUnmarshalMethodInvoke(unmarshal_name, args));
            method.Statements.Add(assign);
        }

        public static CodePrimitiveExpression GetPrimitive(object obj)
        {
            return new CodePrimitiveExpression(obj);
        }

        public static void AddDeferredEmbeddedUnmarshalCall(this CodeMemberMethod method, RpcTypeDescriptor descriptor, string unmarshal_name, string var_name, params RpcMarshalArgument[] additional_args)
        {
            string method_name = null;
            List<CodeExpression> args = new List<CodeExpression>();

            List<CodeTypeReference> marshal_args = new List<CodeTypeReference>();
            marshal_args.Add(descriptor.CodeType);
            marshal_args.AddRange(additional_args.Select(a => a.CodeType));

            method_name = "ReadEmbeddedPointer";
            var create_delegate = new CodeDelegateCreateExpression(CreateFuncType(descriptor.CodeType, marshal_args.Skip(1).ToArray()),
                descriptor.GetUnmarshalTarget(unmarshal_name), descriptor.UnmarshalMethod);
            args.Add(create_delegate);

            args.AddRange(additional_args.Select(r => r.Expression));
            CodeMethodReferenceExpression read_pointer = new CodeMethodReferenceExpression(GetVariable(unmarshal_name), method_name, marshal_args.ToArray());
            CodeMethodInvokeExpression invoke = new CodeMethodInvokeExpression(read_pointer, args.ToArray());
            CodeAssignStatement assign = new CodeAssignStatement(GetVariable(var_name), invoke);
            method.Statements.Add(assign);
        }

        public static void AddPointerUnmarshalCall(this CodeMemberMethod method, RpcTypeDescriptor descriptor, string unmarshal_name, string var_name, params CodeExpression[] additional_args)
        {
            List<CodeExpression> args = new List<CodeExpression>();
            args.AddRange(additional_args);
            CodeAssignStatement assign = new CodeAssignStatement(GetVariable(var_name), descriptor.GetUnmarshalMethodInvoke(unmarshal_name, args));
            CodeAssignStatement assign_null = new CodeAssignStatement(GetVariable(var_name), new CodeDefaultValueExpression(descriptor.GetParameterType()));

            CodeConditionStatement if_statement = new CodeConditionStatement(
                new CodeBinaryOperatorExpression(new CodeMethodInvokeExpression(GetVariable(unmarshal_name), "ReadReferent"), CodeBinaryOperatorType.IdentityInequality, GetPrimitive(0)),
                new CodeStatement[] { assign }, new CodeStatement[] { assign_null });

            method.Statements.Add(if_statement);
        }

        public static void AddPopluateDeferredPointers(this CodeMemberMethod method, string unmarshal_name)
        {
            method.Statements.Add(new CodeMethodInvokeExpression(GetVariable(unmarshal_name), "PopuluateDeferredPointers"));
        }

        public static void AddWriteReferent(this CodeMemberMethod method, string marshal_name, string var_name)
        {
            CodeMethodInvokeExpression invoke = new CodeMethodInvokeExpression(GetVariable(marshal_name), "WriteReferent", GetVariable(var_name));
            method.Statements.Add(invoke);
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

        public static void AddNullCheck(this CodeMemberMethod method, string marshal_name, string var_name)
        {
            CodeMethodInvokeExpression invoke = new CodeMethodInvokeExpression(GetVariable(marshal_name),
                "CheckNull", GetVariable(var_name), GetPrimitive(var_name));
            method.Statements.Add(invoke);
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

        public static void SendReceive(this CodeMemberMethod method, string marshal_name, string unmarshal_name, int proc_num, MarshalHelperBuilder marshal_helper)
        {
            CodeExpression call_sendrecv = new CodeMethodInvokeExpression(null, "SendReceive",
                GetPrimitive(proc_num), new CodeMethodInvokeExpression(GetVariable(marshal_name), "ToArray"), new CodePropertyReferenceExpression(GetVariable(marshal_name), "Handles"));
            call_sendrecv = new CodeObjectCreateExpression(marshal_helper.UnmarshalHelperType, call_sendrecv);
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

        private static Regex _identifier_regex = new Regex(@"[^a-zA-Z0-9_\.]");

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
            if (!correlation.IsConstant && !correlation.IsNormal)
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
                    break;
                default:
                    return false;
            }

            return true;
        }

        public static RpcMarshalArgument CalculateCorrelationArgument(this NdrCorrelationDescriptor correlation,
            int current_offset, IEnumerable<Tuple<int, string>> offset_to_name)
        {
            if (correlation.IsConstant)
            {
                return RpcMarshalArgument.CreateFromPrimitive((long)correlation.Offset);
            }

            int expected_offset = current_offset + correlation.Offset;
            foreach (var offset in offset_to_name)
            {
                if (offset.Item1 == expected_offset)
                {
                    CodeExpression expr = GetVariable(offset.Item2);
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
                    }

                    if (right_expr != null)
                    {
                        expr = new CodeBinaryOperatorExpression(expr, operator_type, right_expr);
                    }
                    return new RpcMarshalArgument(expr, new CodeTypeReference(typeof(long)));
                }
                else if (offset.Item1 > expected_offset)
                {
                    break;
                }
            }

            // We failed to find the base name, just return a 0 for now.
            return RpcMarshalArgument.CreateFromPrimitive(0L);
        }

        public static CodeTypeReference ToRef(this Type type)
        {
            return new CodeTypeReference(type);
        }

        public static CodeTypeReference ToRefArray(this CodeTypeReference type)
        {
            return new CodeTypeReference(type, type.ArrayRank + 1);
        }

        public static CodeTypeReference ToBaseRef(this CodeTypeReference type)
        {
            return type.ArrayElementType ?? type;
        }
    }
}
