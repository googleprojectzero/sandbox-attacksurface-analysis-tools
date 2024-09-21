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

using NtCoreLib.Ndr.Dce;
using NtCoreLib.Ndr.Interop;
using System;
using System.Collections.Generic;
using System.Linq;

#nullable enable

namespace NtCoreLib.Ndr.Rpc;

/// <summary>
/// A parsed NDR RPC_SERVER_INTERFACE structure.
/// </summary>
[Serializable]
public sealed class RpcServerInterface
{
    /// <summary>
    /// The RPC interface ID.
    /// </summary>
    public RpcSyntaxIdentifier InterfaceId { get; }
    /// <summary>
    /// List of syntax info for the server.
    /// </summary>
    public IReadOnlyList<MidlSyntaxInfo> SyntaxInfo { get; }
    /// <summary>
    /// List of protocol sequences.
    /// </summary>
    public IReadOnlyList<RpcProtocolSequenceEndpoint> ProtocolSequences { get; }
    /// <summary>
    /// Get the DCE syntax information (if present).
    /// </summary>
    public MidlSyntaxInfoDce? DceSyntaxInfo { get; }
    /// <summary>
    /// Get the NDR64 syntax information (if present)
    /// </summary>
    public MidlSyntaxInfoNdr64? Ndr64SyntaxInfo { get; }

    internal RpcServerInterface(RPC_SYNTAX_IDENTIFIER interface_id,
        IEnumerable<MidlSyntaxInfo> syntax_info,
        IEnumerable<RpcProtocolSequenceEndpoint> protocol_sequences)
    {
        InterfaceId = new RpcSyntaxIdentifier(interface_id);
        SyntaxInfo = syntax_info.ToList().AsReadOnly();
        ProtocolSequences = protocol_sequences.ToList().AsReadOnly();
        DceSyntaxInfo = SyntaxInfo.OfType<MidlSyntaxInfoDce>().FirstOrDefault();
        Ndr64SyntaxInfo = SyntaxInfo.OfType<MidlSyntaxInfoNdr64>().FirstOrDefault();
    }

    private MidlSyntaxInfoDce? GetDce()
    {
        return SyntaxInfo.OfType<MidlSyntaxInfoDce>().FirstOrDefault();
    }

    internal IReadOnlyList<NdrProcedureDefinition> GetDceProcs()
    {
        return GetDce()?.Procedures ?? Array.Empty<NdrProcedureDefinition>();
    }

    internal IReadOnlyList<NdrComplexTypeReference> GetDceComplexTypes()
    {
        return GetDce()?.ComplexTypes ?? Array.Empty<NdrComplexTypeReference>();
    }

    /// <summary>
    /// Overridden ToString method.
    /// </summary>
    /// <returns>The string form of this class.</returns>
    public override string ToString()
    {
        return InterfaceId.ToString();
    }
}
