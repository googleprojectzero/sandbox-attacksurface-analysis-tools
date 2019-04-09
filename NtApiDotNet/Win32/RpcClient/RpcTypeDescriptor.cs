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

namespace NtApiDotNet.Win32.RpcClient
{
    internal enum RpcPointerType
    {
        None = 0,
        Reference,
        Unique,
        Full
    }

    internal struct RpcMarshalArgument
    {
        public CodeExpression Expression;
        public CodeTypeReference CodeType;

        public RpcMarshalArgument(CodeExpression expression, CodeTypeReference code_type)
        {
            Expression = expression;
            CodeType = code_type;
        }

        public static RpcMarshalArgument CreateFromPrimitive<T>(T primitive)
        {
            return new RpcMarshalArgument(new CodePrimitiveExpression(primitive), new CodeTypeReference(typeof(T)));
        }
    }

    internal sealed class RpcTypeDescriptor
    {
        public CodeTypeReference CodeType { get; }
        public Type BuiltinType { get; }
        public NdrBaseTypeReference NdrType { get; }
        public RpcMarshalArgument[] AdditionalArgs { get; }
        public bool Pointer => PointerType != RpcPointerType.None;
        public RpcPointerType PointerType { get; }
        public bool ValueType { get; }
        public bool Constructed { get; }
        public string UnmarshalMethod { get; }
        public bool UnmarshalGeneric { get; }
        public string MarshalMethod { get; }
        public NdrCorrelationDescriptor ConformanceDescriptor { get; }
        public NdrCorrelationDescriptor VarianceDescriptor { get; }
        public int FixedCount { get; set; }
        public CodeTypeReference UnmarshalHelperType { get; set; }
        public bool UnmarshalHelper => UnmarshalHelperType != null;

        public RpcTypeDescriptor(CodeTypeReference code_type, bool value_type, string unmarshal_method, 
            bool unmarshal_generic, string marshal_method, NdrBaseTypeReference ndr_type,
            NdrCorrelationDescriptor conformance, NdrCorrelationDescriptor variance,
            params RpcMarshalArgument[] additional_args)
        {
            CodeType = code_type;
            UnmarshalMethod = unmarshal_method;
            MarshalMethod = marshal_method;
            UnmarshalGeneric = unmarshal_generic;
            NdrType = ndr_type;
            AdditionalArgs = additional_args;
            ValueType = value_type;
            ConformanceDescriptor = conformance ?? new NdrCorrelationDescriptor();
            VarianceDescriptor = variance ?? new NdrCorrelationDescriptor();
        }

        public RpcTypeDescriptor(Type code_type, string unmarshal_method, bool unmarshal_generic, 
            string marshal_method, NdrBaseTypeReference ndr_type,
            NdrCorrelationDescriptor conformance, NdrCorrelationDescriptor variance,
            params RpcMarshalArgument[] additional_args)
            : this(new CodeTypeReference(code_type), code_type.IsValueType || typeof(NtObject).IsAssignableFrom(code_type), 
                  unmarshal_method, unmarshal_generic, marshal_method, ndr_type, conformance, variance, additional_args)
        {
            BuiltinType = code_type;
        }

        public RpcTypeDescriptor(string name, bool value_type, string unmarshal_method, bool unmarshal_generic, 
            string marshal_method, NdrBaseTypeReference ndr_type,
            NdrCorrelationDescriptor conformance, NdrCorrelationDescriptor variance,
            params RpcMarshalArgument[] additional_args)
            : this(new CodeTypeReference(name), value_type, unmarshal_method, unmarshal_generic, marshal_method, ndr_type, 
                  conformance, variance, additional_args)
        {
            Constructed = true;
        }

        public RpcTypeDescriptor(RpcTypeDescriptor original_desc, RpcPointerType pointer_type)
            : this(original_desc.CodeType, original_desc.ValueType, original_desc.UnmarshalMethod, original_desc.UnmarshalGeneric,
            original_desc.MarshalMethod, original_desc.NdrType, original_desc.ConformanceDescriptor, original_desc.VarianceDescriptor, original_desc.AdditionalArgs)
        {
            PointerType = pointer_type;
            Constructed = original_desc.Constructed;
            FixedCount = original_desc.FixedCount;
            UnmarshalHelperType = original_desc.UnmarshalHelperType;
        }

        public CodeMethodReferenceExpression GetMarshalMethod(CodeExpression target)
        {
            return new CodeMethodReferenceExpression(target, MarshalMethod);
        }

        public CodeExpression GetUnmarshalTarget(string unmarshal_name)
        {
            return CodeGenUtils.GetVariable(unmarshal_name);
        }

        public CodeMethodInvokeExpression GetUnmarshalMethodInvoke(string unmarshal_name, IEnumerable<CodeExpression> additional_args)
        {
            CodeExpression unmarshal_target = GetUnmarshalTarget(unmarshal_name);
            CodeMethodReferenceExpression unmarshal_method;
            if (UnmarshalGeneric)
            {
                unmarshal_method = new CodeMethodReferenceExpression(unmarshal_target, UnmarshalMethod, CodeType.ArrayElementType ?? CodeType);
            }
            else
            {
                unmarshal_method = new CodeMethodReferenceExpression(unmarshal_target, UnmarshalMethod);
            }

            return new CodeMethodInvokeExpression(unmarshal_method, additional_args.ToArray());
        }

        public CodeTypeReference GetStructureType()
        {
            if (Pointer)
            {
                CodeTypeReference ret = new CodeTypeReference(typeof(NdrEmbeddedPointer<>));
                ret.TypeArguments.Add(CodeType);
                return ret;
            }
            return CodeType;
        }

        public CodeTypeReference GetParameterType()
        {
            if (Pointer && ValueType)
            {
                CodeTypeReference ret = new CodeTypeReference(typeof(Nullable<>));
                ret.TypeArguments.Add(CodeType);
                return ret;
            }
            return CodeType;
        }

        public CodeTypeReference GetArrayType()
        {
            return new CodeTypeReference(CodeType, CodeType.ArrayRank + 1);
        }
    }
}
