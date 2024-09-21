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
using System.CodeDom;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace NtApiDotNet.Win32.Rpc
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

        public CodeTypeDeclaration MarshalHelper { get; }
        public CodeTypeDeclaration UnmarshalHelper { get; }
        public CodeTypeReference MarshalHelperType { get;}
        public CodeTypeReference UnmarshalHelperType { get; }

        public Dictionary<NdrBaseTypeReference, CodeMemberMethod> MarshalMethods { get; }
        public Dictionary<NdrBaseTypeReference, CodeMemberMethod> UnmarshalMethods { get; }

        public static CodeTypeDeclaration CreateUnmarshalHelperType(CodeNamespace ns, string name, bool type_decode)
        {
            var type = ns.AddType(name);
            type.TypeAttributes = TypeAttributes.NestedAssembly;
            type.BaseTypes.Add(typeof(NdrUnmarshalBuffer).ToRef());
            var con = type.AddConstructor(MemberAttributes.Public);
            con.AddParam(typeof(RpcClientResponse).ToRef(), "r");
            var param_var = CodeGenUtils.GetVariable("r");

            con.BaseConstructorArgs.Add(new CodePropertyReferenceExpression(param_var, "NdrBuffer"));
            con.BaseConstructorArgs.Add(new CodePropertyReferenceExpression(param_var, "Handles"));
            con.BaseConstructorArgs.Add(new CodePropertyReferenceExpression(param_var, "DataRepresentation"));

            con = type.AddConstructor(MemberAttributes.Public);
            con.AddParam(typeof(byte[]).ToRef(), "ba");
            con.BaseConstructorArgs.Add(CodeGenUtils.GetVariable("ba"));

            if (type_decode)
            {
                con = type.AddConstructor(MemberAttributes.Public);
                con.AddParam(typeof(NdrPickledType).ToRef(), "pickled_type");
                con.BaseConstructorArgs.Add(CodeGenUtils.GetVariable("pickled_type"));
            }

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

        public MarshalHelperBuilder(CodeNamespace ns, string marshal_name, string unmarshal_name, bool type_decode)
        {
            MarshalHelper = CreateMarshalHelperType(ns, marshal_name);
            MarshalHelper.AddStartRegion("Marshal Helpers");
            MarshalHelperType = new CodeTypeReference(MarshalHelper.Name);
            UnmarshalHelper = CreateUnmarshalHelperType(ns, unmarshal_name, type_decode);
            UnmarshalHelper.AddEndRegion();
            UnmarshalHelperType = new CodeTypeReference(UnmarshalHelper.Name);
            MarshalMethods = new Dictionary<NdrBaseTypeReference, CodeMemberMethod>();
            UnmarshalMethods = new Dictionary<NdrBaseTypeReference, CodeMemberMethod>();
        }

        private static CodeExpression AddParam(CodeTypeReference type, int arg_count, CodeMemberMethod method)
        {
            string p_name = $"p{arg_count}";
            method.AddParam(type, p_name);
            return CodeGenUtils.GetVariable(p_name);
        }

        private static CodeMemberMethod AddMethod(CodeTypeDeclaration marshal_type, string method_name, CodeTypeReference generic_type, CodeTypeReference return_type, 
            string name, CodeTypeReference[] pre_args, AdditionalArguments additional_args)
        {
            var method = marshal_type.AddMethod(method_name, MemberAttributes.Public | MemberAttributes.Final);
            method.ReturnType = return_type;
            int arg_count = 0;

            List<CodeExpression> arg_names = new List<CodeExpression>(pre_args.Select(a => AddParam(a, arg_count++, method)));
            arg_names.AddRange(additional_args.FixedArgs);
            arg_names.AddRange(additional_args.Params.Select(a => AddParam(a, arg_count++, method)));

            CodeMethodReferenceExpression generic_method = generic_type != null ? new CodeMethodReferenceExpression(null, name, generic_type) : new CodeMethodReferenceExpression(null, name);
            var invoke_method = new CodeMethodInvokeExpression(generic_method, arg_names.ToArray());
            if (return_type != null)
            {
                method.AddReturn(invoke_method);
            }
            else
            {
                method.Statements.Add(invoke_method);
            }

            return method;
        }

        public string AddGenericUnmarshal(NdrBaseTypeReference ndr_type, CodeTypeReference type, string name, AdditionalArguments additional_args)
        {
            CodeTypeReference generic_type = additional_args.Generic ? (additional_args.GenericType ?? type.ToBaseRef()) : null;
            var method = AddMethod(UnmarshalHelper, $"Read_{_current_unmarshal_id++}", generic_type, type, name, new CodeTypeReference[0], additional_args);
            UnmarshalMethods.Add(ndr_type, method);
            return method.Name;
        }

        public string AddGenericMarshal(NdrBaseTypeReference ndr_type, CodeTypeReference type, string name, AdditionalArguments additional_args)
        {
            CodeTypeReference generic_type = additional_args.Generic ? (additional_args.GenericType ?? type.ToBaseRef()) : null;
            var method = AddMethod(MarshalHelper, $"Write_{_current_marshal_id++}", generic_type, null, name, new[] { type }, additional_args);
            MarshalMethods.Add(ndr_type, method);
            return method.Name;
        }

        public string AddGenericMarshal(NdrBaseTypeReference ndr_type, string type_name, string name, AdditionalArguments additional_args)
        {
            return AddGenericMarshal(ndr_type, new CodeTypeReference(CodeGenUtils.MakeIdentifier(type_name)), name, additional_args);
        }
    }
}
