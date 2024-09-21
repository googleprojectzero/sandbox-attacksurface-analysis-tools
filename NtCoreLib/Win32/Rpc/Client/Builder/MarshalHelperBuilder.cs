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

using NtCoreLib.Ndr.Dce;
using NtCoreLib.Ndr.Marshal;
using System;
using System.CodeDom;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace NtCoreLib.Win32.Rpc.Client.Builder;

internal class MarshalHelperBuilder
{
    private int _current_unmarshal_id;
    private int _current_marshal_id;

    public CodeExpression CastUnmarshal(CodeExpression expr)
    {
        return new CodeObjectCreateExpression(UnmarshalHelperType, expr);
    }

    public CodeExpression CastMarshal(CodeExpression expr)
    {
        return new CodeObjectCreateExpression(MarshalHelperType, expr);
    }

    public string AddGenericUnmarshal(NdrBaseTypeReference ndr_type, CodeTypeReference type, string name, AdditionalArguments additional_args)
    {
        CodeTypeReference generic_type = additional_args.Generic ? additional_args.GenericType ?? type.ToBaseRef() : null;
        var method = AddMethod(UnmarshalHelper, $"Read_{_current_unmarshal_id++}", generic_type, type, name, new CodeTypeReference[0], additional_args);
        UnmarshalMethods.Add(ndr_type, method);
        return method.Name;
    }

    public string AddGenericMarshal(NdrBaseTypeReference ndr_type, CodeTypeReference type, string name, AdditionalArguments additional_args)
    {
        CodeTypeReference generic_type = additional_args.Generic ? additional_args.GenericType ?? type.ToBaseRef() : null;
        var method = AddMethod(MarshalHelper, $"Write_{_current_marshal_id++}", generic_type, null, name, new[] { type }, additional_args);
        MarshalMethods.Add(ndr_type, method);
        return method.Name;
    }

    public string AddGenericMarshal(NdrBaseTypeReference ndr_type, string type_name, string name, AdditionalArguments additional_args)
    {
        return AddGenericMarshal(ndr_type, new CodeTypeReference(CodeGenUtils.MakeIdentifier(type_name)), name, additional_args);
    }

    public RpcTypeDescriptor GetContextHandleType(NdrSupplementTypeReference supplement_type)
    {
        if (_strict_context_handles.TryGetValue(supplement_type.Argument2, out RpcTypeDescriptor type_desc))
            return type_desc;

        var type = _add_type($"TypeStrictContextHandle_{supplement_type.Argument2}");
        type.TypeAttributes = TypeAttributes.Public | TypeAttributes.Sealed;
        type.BaseTypes.Add(new CodeTypeReference(typeof(NdrTypeStrictContextHandle)));

        if (_last_context_handle == null)
        {
            type.AddStartRegion("Type Strict Context Handles");
        }

        _last_context_handle?.EndDirectives.Clear();
        _last_context_handle = type;
        _last_context_handle.AddEndRegion();

        string unmarshal_name = nameof(NdrUnmarshalBuffer.ReadContextHandle);
        string marshal_name = nameof(NdrMarshalBuffer.WriteContextHandle);
        AdditionalArguments args = new(true);
        type_desc = new RpcTypeDescriptor(new CodeTypeReference(type.Name), false, unmarshal_name, this, marshal_name,
            supplement_type, null, null, null, args);
        _strict_context_handles.Add(supplement_type.Argument2, type_desc);
        return type_desc;
    }

    public CodeTypeDeclaration MarshalHelper { get; }
    public CodeTypeDeclaration UnmarshalHelper { get; }
    public CodeTypeReference MarshalHelperType { get; }
    public CodeTypeReference UnmarshalHelperType { get; }

    public Dictionary<NdrBaseTypeReference, CodeMemberMethod> MarshalMethods { get; }
    public Dictionary<NdrBaseTypeReference, CodeMemberMethod> UnmarshalMethods { get; }

    public MarshalHelperBuilder(Func<string, CodeTypeDeclaration> add_type, bool private_types, string marshal_name, string unmarshal_name, bool type_decode)
    {
        _add_type = add_type;
        MarshalHelper = CreateMarshalHelperType(add_type, private_types, marshal_name);
        MarshalHelper.AddStartRegion("Marshal Helpers");
        MarshalHelperType = new CodeTypeReference(MarshalHelper.Name);
        UnmarshalHelper = CreateUnmarshalHelperType(add_type, private_types, unmarshal_name, type_decode);
        UnmarshalHelper.AddEndRegion();
        UnmarshalHelperType = new CodeTypeReference(UnmarshalHelper.Name);
        MarshalMethods = new Dictionary<NdrBaseTypeReference, CodeMemberMethod>();
        UnmarshalMethods = new Dictionary<NdrBaseTypeReference, CodeMemberMethod>();
    }

    #region Private Members
    private readonly Func<string, CodeTypeDeclaration> _add_type;
    private readonly Dictionary<int, RpcTypeDescriptor> _strict_context_handles = new();
    private CodeTypeDeclaration _last_context_handle;

    private static CodeTypeDeclaration CreateUnmarshalHelperType(Func<string, CodeTypeDeclaration> add_type, bool private_types, string name, bool type_decode)
    {
        var type = add_type(name);
        if (private_types)
        {
            type.TypeAttributes = TypeAttributes.Sealed | TypeAttributes.NestedPrivate;
        }
        else
        {
            type.TypeAttributes = TypeAttributes.NestedAssembly | TypeAttributes.Sealed;
        }
        type.BaseTypes.Add(typeof(NdrUnmarshalBufferDelegator).ToRef());
        var con = type.AddConstructor(MemberAttributes.Public);
        con.AddParam(typeof(INdrUnmarshalBuffer).ToRef(), "u");
        con.BaseConstructorArgs.Add(CodeGenUtils.GetVariable("u"));

        if (type_decode)
        {
            con = type.AddConstructor(MemberAttributes.Public);
            con.AddParam(typeof(NdrPickledType).ToRef(), "pickled_type");
            con.BaseConstructorArgs.Add(CodeGenUtils.GetVariable("pickled_type"));
        }

        return type;
    }

    private static CodeTypeDeclaration CreateMarshalHelperType(Func<string, CodeTypeDeclaration> add_type, bool private_types, string name)
    {
        var type = add_type(name);
        var con = type.AddConstructor(MemberAttributes.Public);
        con.ChainedConstructorArgs.Add(new CodeObjectCreateExpression(typeof(NdrMarshalBuffer).ToRef()));
        con = type.AddConstructor(MemberAttributes.Public);
        con.AddParam(typeof(INdrMarshalBuffer).ToRef(), "m");
        con.BaseConstructorArgs.Add(CodeGenUtils.GetVariable("m"));
        if (private_types)
        {
            type.TypeAttributes = TypeAttributes.Sealed | TypeAttributes.NestedPrivate;
        }
        else
        {
            type.TypeAttributes = TypeAttributes.NestedAssembly | TypeAttributes.Sealed;
        }
        type.BaseTypes.Add(new CodeTypeReference(typeof(NdrMarshalBufferDelegator)));
        return type;
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

        List<CodeExpression> arg_names = new(pre_args.Select(a => AddParam(a, arg_count++, method)));
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
    #endregion
}
