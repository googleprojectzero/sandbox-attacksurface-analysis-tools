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
using System.CodeDom;
using System.Reflection;

namespace NtApiDotNet.Win32.RpcClient
{
    internal class MarshalHelperBuilder
    {
        private int _current_unmarshal_id;
        private int _current_marshal_id;

        public CodeExpression CastUnmarshal(CodeExpression expr)
        {
            return new CodeCastExpression(UnmarshalHelperType, expr);
        }

        public CodeExpression CastMarshal(CodeExpression expr)
        {
            return new CodeCastExpression(MarshalHelperType, expr);
        }

        public CodeExpression WrapUnmarshal(CodeExpression target)
        {
            return new CodeObjectCreateExpression(UnmarshalHelperType, target);
        }

        public CodeExpression WrapMarshal(CodeExpression target)
        {
            return new CodeObjectCreateExpression(MarshalHelperType, target);
        }

        public CodeTypeDeclaration MarshalHelper { get; }
        public CodeTypeDeclaration UnmarshalHelper { get; }
        public CodeTypeReference MarshalHelperType { get;}
        public CodeTypeReference UnmarshalHelperType { get; }

        public static CodeTypeDeclaration CreateUnmarshalHelperType(CodeNamespace ns, string name)
        {
            var unmarshal_type = new CodeTypeReference(typeof(NdrUnmarshalBuffer));
            var type = ns.AddType(name);
            type.TypeAttributes = TypeAttributes.NestedAssembly;
            type.BaseTypes.Add(unmarshal_type);
            var con = type.AddConstructor(MemberAttributes.Public);
            con.AddParam(unmarshal_type, "u");
            con.BaseConstructorArgs.Add(CodeGenUtils.GetVariable("u"));
            return type;
        }

        public static CodeTypeDeclaration CreateMarshalHelperType(CodeNamespace ns, string name)
        {
            var marshal_type = new CodeTypeReference(typeof(NdrMarshalBuffer));
            var type = ns.AddType(name);
            type.TypeAttributes = TypeAttributes.NestedAssembly;
            type.BaseTypes.Add(marshal_type);
            return type;
        }

        public MarshalHelperBuilder(CodeNamespace ns, string marshal_name, string unmarshal_name)
        {
            MarshalHelper = CreateMarshalHelperType(ns, marshal_name);
            MarshalHelper.AddStartRegion("Marshal Helpers");
            MarshalHelperType = new CodeTypeReference(MarshalHelper.Name);
            UnmarshalHelper = CreateUnmarshalHelperType(ns, unmarshal_name);
            UnmarshalHelper.AddEndRegion();
            UnmarshalHelperType = new CodeTypeReference(UnmarshalHelper.Name);
        }

        private static CodeMemberMethod AddMethod(CodeTypeDeclaration marshal_type, string method_name, CodeTypeReference type, string name, params CodeTypeReference[] args)
        {
            var method = marshal_type.AddMethod(method_name, MemberAttributes.Public | MemberAttributes.Final);
            method.ReturnType = type;
            CodeVariableReferenceExpression[] arg_names = new CodeVariableReferenceExpression[args.Length];
            for (int i = 0; i < args.Length; ++i)
            {
                string p_name = $"p{i}";
                method.AddParam(args[i], p_name);
                arg_names[i] = CodeGenUtils.GetVariable(p_name);
            }

            CodeMethodReferenceExpression generic_method = new CodeMethodReferenceExpression(null, name, type);
            method.AddReturn(new CodeMethodInvokeExpression(generic_method, arg_names));

            return method;
        }

        public CodeMemberMethod AddGenericUnmarshal(CodeTypeReference type, string name, params CodeTypeReference[] args)
        {
            return AddMethod(UnmarshalHelper, $"Read_{_current_unmarshal_id++}", type, name, args);
        }

        public CodeMemberMethod AddGenericUnmarshal(string type_name, string name, params CodeTypeReference[] args)
        {
            return AddGenericUnmarshal(new CodeTypeReference(CodeGenUtils.MakeIdentifier(type_name)), name, args);
        }

        public CodeMemberMethod AddGenericMarshal(CodeTypeReference type, string name, params CodeTypeReference[] args)
        {
            return AddMethod(MarshalHelper, $"Write_{_current_marshal_id++}", type, name, args);
        }

        public CodeMemberMethod AddGenericMarshal(string type_name, string name, params CodeTypeReference[] args)
        {
            return AddGenericMarshal(new CodeTypeReference(CodeGenUtils.MakeIdentifier(type_name)), name, args);
        }
    }
}
