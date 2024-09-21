//  Copyright 2020 Google Inc. All Rights Reserved.
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

using NtCoreLib.Ndr.Rpc;
using System;
using System.Collections.Generic;
using System.IO;

namespace NtCoreLib.Win32.Rpc.Transport.PDU;

[Flags]
internal enum BindTimeFeatureNegotiation
{
    None = 0,
    SecurityContextMultiplexingSupported = 1,
    KeepConnectionOnOrphanSupported = 2,
}

internal sealed class ContextElement
{
    public ushort ContextId { get; set; }
    public RpcSyntaxIdentifier AbstractSyntax { get; set; }
    public List<RpcSyntaxIdentifier> TransferSyntax { get; }

    public ContextElement()
    {
        TransferSyntax = new List<RpcSyntaxIdentifier>();
    }

    public ContextElement(RpcSyntaxIdentifier interface_id, RpcSyntaxIdentifier transfer_syntax) 
        : this()
    {
        AbstractSyntax = interface_id;
        TransferSyntax.Add(transfer_syntax);
    }

    public ContextElement(RpcSyntaxIdentifier interface_id, BindTimeFeatureNegotiation negotiation_flags)
        : this(interface_id, GetNegotiationGuid(negotiation_flags))
    {
    }

    private static RpcSyntaxIdentifier GetNegotiationGuid(BindTimeFeatureNegotiation negotiation_flags)
    {
        return new RpcSyntaxIdentifier(new Guid(0x6CB71C2C, unchecked((short)0x9812),
            0x4540, BitConverter.GetBytes((long)negotiation_flags)), new RpcVersion(1, 0));
    }

    private void WriteSyntax(BinaryWriter writer, RpcSyntaxIdentifier syntax)
    {
        writer.Write(syntax.Uuid.ToByteArray());
        writer.Write(syntax.Version.Major);
        writer.Write(syntax.Version.Minor);
    }

    private void Write(BinaryWriter writer)
    {
        writer.Write(ContextId);
        writer.Write((byte)TransferSyntax.Count);
        writer.Write((byte)0); // reserved.
        WriteSyntax(writer, AbstractSyntax);
        foreach (var transfer in TransferSyntax)
        {
            WriteSyntax(writer, transfer);
        }
    }

    public static void WriteList(BinaryWriter writer, List<ContextElement> elements)
    {
        // Relies on little endian ordering to write the two reserved fields.
        writer.Write(elements.Count);
        foreach (var e in elements)
        {
            e.Write(writer);
        }
    }
}
