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

using NtApiDotNet.Ndr;
using System;
using System.Collections.Generic;
using System.IO;

namespace NtApiDotNet.Win32.Rpc.Transport.PDU
{
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
        public RPC_SYNTAX_IDENTIFIER AbstractSyntax { get; set; }
        public List<RPC_SYNTAX_IDENTIFIER> TransferSyntax { get; }

        private static RPC_SYNTAX_IDENTIFIER ToSyntax(Guid id, Version version)
        {
            return new RPC_SYNTAX_IDENTIFIER(id, (ushort)version.Major, (ushort)version.Minor);
        }

        public ContextElement()
        {
            TransferSyntax = new List<RPC_SYNTAX_IDENTIFIER>();
        }

        public ContextElement(Guid interface_id, Version interface_version, Guid transfer_syntax_id, Version transfer_syntax_version) 
            : this()
        {
            AbstractSyntax = ToSyntax(interface_id, interface_version);
            TransferSyntax.Add(ToSyntax(transfer_syntax_id, transfer_syntax_version));
        }

        public ContextElement(Guid interface_id, Version interface_version, BindTimeFeatureNegotiation negotiation_flags)
            : this(interface_id, interface_version, GetNegotiationGuid(negotiation_flags), new Version(1, 0))
        {
        }

        private static Guid GetNegotiationGuid(BindTimeFeatureNegotiation negotiation_flags)
        {
            return new Guid(0x6CB71C2C, unchecked((short)0x9812), 
                0x4540, BitConverter.GetBytes((long)negotiation_flags));
        }

        private void WriteSyntax(BinaryWriter writer, RPC_SYNTAX_IDENTIFIER syntax)
        {
            writer.Write(syntax.SyntaxGUID.ToByteArray());
            writer.Write(syntax.SyntaxVersion.MajorVersion);
            writer.Write(syntax.SyntaxVersion.MinorVersion);
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
}
