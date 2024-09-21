//  Copyright 2018 Google Inc. All Rights Reserved.
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


#nullable enable

using NtCoreLib.Ndr.Ndr64;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtCoreLib.Ndr.Rpc;

/// <summary>
/// Syntax information for NDR64
/// </summary>
[Serializable]
public sealed class MidlSyntaxInfoNdr64 : MidlSyntaxInfo
{
    private readonly Ndr64TypeCache _type_cache;

    /// <summary>
    /// List of parsed procedures.
    /// </summary>
    public IReadOnlyList<Ndr64ProcedureDefinition> Procedures { get; }

    /// <summary>
    /// List of parsed types.
    /// </summary>
    public IReadOnlyList<Ndr64BaseTypeReference> Types => _type_cache.Types.ToList().AsReadOnly();

    /// <summary>
    /// List of complex types.
    /// </summary>
    public IReadOnlyList<Ndr64ComplexTypeReference> ComplexTypes => _type_cache.ComplexTypes.ToList().AsReadOnly();

    internal MidlSyntaxInfoNdr64(IEnumerable<Ndr64ProcedureDefinition> procs,
        Ndr64TypeCache type_cache) : base(RpcSyntaxIdentifier.NDR64TransferSyntax)
    {
        Procedures = procs.ToList().AsReadOnly();
        _type_cache = type_cache;
    }
}
