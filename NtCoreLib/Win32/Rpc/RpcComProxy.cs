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
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Rpc
{
    /// <summary>
    /// Representation of a COM proxy.
    /// </summary>
    [Serializable]
    public sealed class RpcComProxy : IRpcBuildableClient
    {
        /// <summary>
        /// The COM proxy definition.
        /// </summary>
        public NdrComProxyDefinition Proxy { get; }

        /// <inheritdoc/>
        public Guid InterfaceId => Proxy.Iid;

        /// <inheritdoc/>
        public Version InterfaceVersion => new Version();

        /// <inheritdoc/>
        public IEnumerable<NdrProcedureDefinition> Procedures => Proxy.Procedures;

        /// <inheritdoc/>
        public IEnumerable<NdrComplexTypeReference> ComplexTypes { get; }

        /// <inheritdoc/>
        public string FilePath => string.Empty;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="proxy">The proxy definition to create from.</param>
        public RpcComProxy(NdrComProxyDefinition proxy)
        {
            Proxy = proxy;
            ComplexTypes = GetComplexTypes(proxy);
        }

        private static IEnumerable<NdrBaseTypeReference> GetStructTypes(NdrComplexTypeReference complex_type)
        {
            if (complex_type is NdrBaseStructureTypeReference struct_type)
            {
                return struct_type.MembersTypes;
            }
            else if (complex_type is NdrUnionTypeReference union_type)
            {
                return union_type.Arms.Arms.Select(a => a.ArmType);
            }
            return Array.Empty<NdrBaseTypeReference>();
        }

        private static void GetComplexTypes(HashSet<NdrComplexTypeReference> complex_types, NdrBaseTypeReference type)
        {
            if (type is NdrComplexTypeReference complex_type)
            {
                if (complex_types.Add(complex_type))
                {
                    foreach (var member_type in GetStructTypes(complex_type))
                    {
                        GetComplexTypes(complex_types, member_type);
                    }
                }
            }
            else if (type is NdrBaseArrayTypeReference array_type)
            {
                GetComplexTypes(complex_types, array_type.ElementType);
            }
            else if (type is NdrPointerTypeReference pointer_type)
            {
                GetComplexTypes(complex_types, pointer_type.Type);
            }
        }

        private static IEnumerable<NdrComplexTypeReference> GetComplexTypes(NdrComProxyDefinition proxy)
        {
            HashSet<NdrComplexTypeReference> complex_types = new HashSet<NdrComplexTypeReference>();
            foreach (var proc in proxy.Procedures)
            {
                GetComplexTypes(complex_types, proc.ReturnValue.Type);
                foreach (var p in proc.Params)
                {
                    GetComplexTypes(complex_types, p.Type);
                }
            }
            return complex_types;
        }
    }
}