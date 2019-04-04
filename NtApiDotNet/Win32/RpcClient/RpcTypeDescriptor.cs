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

namespace NtApiDotNet.Win32.RpcClient
{
    internal sealed class RpcTypeDescriptor
    {
        public string UnmarshalMethod { get; }
        public string MarshalMethod { get; }
        public CodeTypeReference CodeType { get; }
        public Type BuiltinType { get; }
        public NdrBaseTypeReference NdrType { get; }
        public CodeExpression[] AdditionalArgs { get; }
        public bool Pointer { get; }
        public bool ValueType { get; }

        public RpcTypeDescriptor(CodeTypeReference code_type, bool value_type, string unmarshal_method, string marshal_method, NdrBaseTypeReference ndr_type, params CodeExpression[] additional_args)
        {
            CodeType = code_type;
            UnmarshalMethod = unmarshal_method;
            MarshalMethod = marshal_method;
            NdrType = ndr_type;
            AdditionalArgs = additional_args;
            ValueType = value_type;
        }

        public RpcTypeDescriptor(Type code_type, string unmarshal_method, string marshal_method, NdrBaseTypeReference ndr_type, params CodeExpression[] additional_args)
            : this(new CodeTypeReference(code_type), code_type.IsValueType || typeof(NtObject).IsAssignableFrom(code_type), unmarshal_method, marshal_method, ndr_type, additional_args)
        {
            BuiltinType = code_type;
        }

        public RpcTypeDescriptor(string name, bool value_type, string unmarshal_method, string marshal_method, NdrBaseTypeReference ndr_type, params CodeExpression[] additional_args)
            : this(new CodeTypeReference(name), value_type, unmarshal_method, marshal_method, ndr_type, additional_args)
        {
        }

        private static CodeTypeReference CreateType(RpcTypeDescriptor original_desc)
        {
            if (original_desc.ValueType)
            {
                var ret = new CodeTypeReference(typeof(Nullable<>));
                ret.TypeArguments.Add(original_desc.CodeType);
                return ret;
            }
            return original_desc.CodeType;
        }

        public RpcTypeDescriptor(RpcTypeDescriptor original_desc, bool pointer)
            : this(CreateType(original_desc), false, original_desc.UnmarshalMethod,
            original_desc.MarshalMethod, original_desc.NdrType, original_desc.AdditionalArgs)
        {
            Pointer = pointer;
        }
    }
}
