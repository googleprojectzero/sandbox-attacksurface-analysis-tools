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

using System;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Ndr
{
    /// <summary>
    /// A parsed NDR RPC_SERVER_INTERFACE structure.
    /// </summary>
    [Serializable]
    public class NdrRpcServerInterface
    {
        /// <summary>
        /// The RPC interface GUID.
        /// </summary>
        public Guid InterfaceId { get; }
        /// <summary>
        /// The RPC interface version.
        /// </summary>
        public Version InterfaceVersion { get; }
        /// <summary>
        /// The RPC transfer syntax GUID.
        /// </summary>
        public Guid TransferSyntaxId { get; }
        /// <summary>
        /// The RPC transfer syntax version.
        /// </summary>
        public Version TransferSyntaxVersion { get; }
        /// <summary>
        /// List of parsed procedures.
        /// </summary>
        public IList<NdrProcedureDefinition> Procedures { get; }
        /// <summary>
        /// List of protocol sequences.
        /// </summary>
        public IList<NdrProtocolSequenceEndpoint> ProtocolSequences { get; }

        internal NdrRpcServerInterface(RPC_SYNTAX_IDENTIFIER interface_id, 
            RPC_SYNTAX_IDENTIFIER transfer_syntax_id, IEnumerable<NdrProcedureDefinition> procedures,
            IEnumerable<NdrProtocolSequenceEndpoint> protocol_sequences)
        {
            InterfaceId = interface_id.SyntaxGUID;
            InterfaceVersion = new Version(interface_id.SyntaxVersion.MajorVersion, interface_id.SyntaxVersion.MinorVersion);
            TransferSyntaxId = transfer_syntax_id.SyntaxGUID;
            TransferSyntaxVersion = new Version(transfer_syntax_id.SyntaxVersion.MajorVersion, transfer_syntax_id.SyntaxVersion.MinorVersion);
            Procedures = procedures.ToList().AsReadOnly();
            ProtocolSequences = protocol_sequences.ToList().AsReadOnly();
        }

        internal string Format(NdrFormatter context)
        {
            NdrStringBuilder builder = new NdrStringBuilder();
            builder.AppendLine("[uuid(\"{0}\"), version({1})]", InterfaceId, InterfaceVersion);
            builder.AppendLine("interface intf_{0} {{", InterfaceId.ToString().Replace('-','_'));
            builder.PushIndent(' ', 4);
            foreach (NdrProcedureDefinition proc in Procedures)
            {
                builder.AppendLine(proc.FormatProcedure(context));
            }
            builder.PopIndent();
            builder.AppendLine("}").AppendLine();
            return builder.ToString();
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The string form of this class.</returns>
        public override string ToString()
        {
            return $"UUID: {InterfaceId}";
        }
    }
}
