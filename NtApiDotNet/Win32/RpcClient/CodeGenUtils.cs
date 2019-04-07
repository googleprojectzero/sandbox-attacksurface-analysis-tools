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

        public static CodeMemberMethod AddMarshalMethod(this CodeTypeDeclaration type, string marshal_name)
        {
            CodeMemberMethod method = type.AddMethod("Marshal", MemberAttributes.Final | MemberAttributes.Private);
            method.PrivateImplementationType = new CodeTypeReference(typeof(INdrStructure));
            method.AddParam(typeof(NdrMarshalBuffer), marshal_name);
            return method;
        }

        public static void AddAlign(this CodeMemberMethod method, string marshal_name, int align)
        {
            method.Statements.Add(new CodeMethodInvokeExpression(new CodeVariableReferenceExpression(marshal_name), "Align", GetPrimitive(align)));
        }

        public static CodeMemberMethod AddUnmarshalMethod(this CodeTypeDeclaration type, string unmarshal_name)
        {
            CodeMemberMethod method = type.AddMethod("Unmarshal", MemberAttributes.Final | MemberAttributes.Private);
            method.PrivateImplementationType = new CodeTypeReference(typeof(INdrStructure));
            method.AddParam(typeof(NdrUnmarshalBuffer), unmarshal_name);
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

        public static void AddConstructorMethod(this CodeTypeDeclaration type, string name, RpcTypeDescriptor complex_type)
        {
            CodeMemberMethod method = type.AddMethod($"New{MakeIdentifier(name)}", MemberAttributes.Public | MemberAttributes.Final);
            method.ReturnType = complex_type.CodeType;
            method.Statements.Add(new CodeMethodReturnStatement(new CodeObjectCreateExpression(complex_type.CodeType)));
        }

        public static CodeVariableReferenceExpression GetVariable(string var_name)
        {
            return new CodeVariableReferenceExpression(MakeIdentifier(var_name));
        }

        public static void AddMarshalCall(this CodeMemberMethod method, RpcTypeDescriptor descriptor, string marshal_name, string var_name, params RpcMarshalArgument[] additional_args)
        {
            List<CodeExpression> args = new List<CodeExpression>
            {
                GetVariable(var_name)
            };
            args.AddRange(descriptor.AdditionalArgs.Select(r => r.Expression));
            args.AddRange(additional_args.Select(r => r.Expression));
            CodeMethodInvokeExpression invoke = new CodeMethodInvokeExpression(descriptor.GetMarshalMethod(GetVariable(marshal_name)), args.ToArray());
            method.Statements.Add(invoke);
        }

        public static void AddFlushDeferredWrites(this CodeMemberMethod method, string marshal_name)
        {
            method.Statements.Add(new CodeMethodInvokeExpression(GetVariable(marshal_name), "FlushDeferredWrites"));
        }

        public static void AddDeferredMarshalCall(this CodeMemberMethod method, RpcTypeDescriptor descriptor, string marshal_name, string var_name, params RpcMarshalArgument[] additional_args)
        {
            List<CodeExpression> args = new List<CodeExpression>
            {
                GetVariable(var_name)
            };

            args.Add(descriptor.GetMarshalMethod(GetVariable(marshal_name)));
            args.AddRange(descriptor.AdditionalArgs.Select(r => r.Expression));
            args.AddRange(additional_args.Select(r => r.Expression));
            CodeMethodReferenceExpression write_pointer = new CodeMethodReferenceExpression(GetVariable(marshal_name), "WriteEmbeddedPointer", descriptor.CodeType);
            CodeMethodInvokeExpression invoke = new CodeMethodInvokeExpression(write_pointer, args.ToArray());
            method.Statements.Add(invoke);
        }

        public static void AddUnmarshalCall(this CodeMemberMethod method, RpcTypeDescriptor descriptor, string unmarshal_name, string var_name, params CodeExpression[] additional_args)
        {
            List<CodeExpression> args = new List<CodeExpression>();
            args.AddRange(descriptor.AdditionalArgs.Select(r => r.Expression));
            args.AddRange(additional_args);

            CodeAssignStatement assign = new CodeAssignStatement(GetVariable(var_name), new CodeMethodInvokeExpression(descriptor.GetUnmarshalMethod(GetVariable(unmarshal_name)), args.ToArray()));
            method.Statements.Add(assign);
        }

        public static CodePrimitiveExpression GetPrimitive(object obj)
        {
            return new CodePrimitiveExpression(obj);
        }

        public static void AddDeferredEmbeddedUnmarshalCall(this CodeMemberMethod method, RpcTypeDescriptor descriptor, string unmarshal_name, string var_name, params CodeExpression[] additional_args)
        {
            List<CodeExpression> args = new List<CodeExpression>();
            args.Add(descriptor.GetUnmarshalMethod(GetVariable(unmarshal_name)));
            args.AddRange(descriptor.AdditionalArgs.Select(r => r.Expression));
            args.AddRange(additional_args);
            CodeMethodReferenceExpression read_pointer = new CodeMethodReferenceExpression(GetVariable(unmarshal_name), "ReadEmbeddedPointer", descriptor.CodeType);
            CodeMethodInvokeExpression invoke = new CodeMethodInvokeExpression(read_pointer, args.ToArray());
            CodeAssignStatement assign = new CodeAssignStatement(GetVariable(var_name), invoke);
            method.Statements.Add(assign);
        }

        public static void AddPointerUnmarshalCall(this CodeMemberMethod method, RpcTypeDescriptor descriptor, string unmarshal_name, string var_name, params CodeExpression[] additional_args)
        {
            List<CodeExpression> args = new List<CodeExpression>();
            args.AddRange(descriptor.AdditionalArgs.Select(r => r.Expression));
            args.AddRange(additional_args);
            CodeAssignStatement assign = new CodeAssignStatement(GetVariable(var_name), new CodeMethodInvokeExpression(descriptor.GetUnmarshalMethod(GetVariable(unmarshal_name)), args.ToArray()));
            CodeAssignStatement assign_null = new CodeAssignStatement(GetVariable(var_name), new CodeDefaultValueExpression(descriptor.CodeType));

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
            List<CodeExpression> args = new List<CodeExpression>();
            args.AddRange(descriptor.AdditionalArgs.Select(r => r.Expression));
            args.AddRange(additional_args.Select(r => r.Expression));
            CodeMethodReturnStatement ret = new CodeMethodReturnStatement(new CodeMethodInvokeExpression(descriptor.GetUnmarshalMethod(GetVariable(unmarshal_name)), args.ToArray()));
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

        public static void CreateMarshalObject(this CodeMemberMethod method, string name)
        {
            method.Statements.Add(new CodeVariableDeclarationStatement(typeof(NdrMarshalBuffer), name, new CodeObjectCreateExpression(typeof(NdrMarshalBuffer))));
        }

        public static void SendReceive(this CodeMemberMethod method, string marshal_name, string unmarshal_name, int proc_num)
        {
            CodeMethodInvokeExpression call_sendrecv = new CodeMethodInvokeExpression(null, "SendReceive",
                GetPrimitive(proc_num), GetVariable(marshal_name));
            CodeVariableDeclarationStatement unmarshal = new CodeVariableDeclarationStatement(typeof(NdrUnmarshalBuffer), unmarshal_name, call_sendrecv);
            method.Statements.Add(unmarshal);
        }

        private static Regex _identifier_regex = new Regex(@"[^a-zA-Z0-9_\.]");

        public static string MakeIdentifier(string id)
        {
            id = _identifier_regex.Replace(id, "_");
            if (!char.IsLetter(id[0]))
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

        public static Type GetBuiltinType(this NdrBaseTypeReference type)
        {
            if (type is NdrSimpleTypeReference)
            {
                switch (type.Format)
                {
                    case NdrFormatCharacter.FC_BYTE:
                    case NdrFormatCharacter.FC_USMALL:
                        return typeof(byte);
                    case NdrFormatCharacter.FC_SMALL:
                    case NdrFormatCharacter.FC_CHAR:
                        return typeof(sbyte);
                    case NdrFormatCharacter.FC_WCHAR:
                        return typeof(char);
                    case NdrFormatCharacter.FC_SHORT:
                        return typeof(short);
                    case NdrFormatCharacter.FC_USHORT:
                        return typeof(ushort);
                    case NdrFormatCharacter.FC_LONG:
                        return typeof(int);
                    case NdrFormatCharacter.FC_ULONG:
                        return typeof(uint);
                    case NdrFormatCharacter.FC_FLOAT:
                        return typeof(float);
                    case NdrFormatCharacter.FC_HYPER:
                        return typeof(long);
                    case NdrFormatCharacter.FC_DOUBLE:
                        return typeof(double);
                    case NdrFormatCharacter.FC_INT3264:
                        return typeof(NdrInt3264);
                    case NdrFormatCharacter.FC_UINT3264:
                        return typeof(NdrUInt3264);
                    case NdrFormatCharacter.FC_C_WSTRING:
                    case NdrFormatCharacter.FC_WSTRING:
                    case NdrFormatCharacter.FC_C_CSTRING:
                    case NdrFormatCharacter.FC_CSTRING:
                        return typeof(string);
                    case NdrFormatCharacter.FC_ENUM16:
                        return typeof(int);
                    case NdrFormatCharacter.FC_ENUM32:
                        return typeof(int);
                    case NdrFormatCharacter.FC_SYSTEM_HANDLE:
                        return typeof(IntPtr);
                    case NdrFormatCharacter.FC_ERROR_STATUS_T:
                        return typeof(uint);
                }

            }
            else if (type is NdrKnownTypeReference known_type)
            {
                switch (known_type.KnownType)
                {
                    case NdrKnownTypes.GUID:
                        return typeof(Guid);
                    case NdrKnownTypes.BSTR:
                        return typeof(string);
                    case NdrKnownTypes.HSTRING:
                        return typeof(string);
                }
            }
            else if (type is NdrBaseStringTypeReference)
            {
                return typeof(string);
            }

            return null;
        }
    }
}
