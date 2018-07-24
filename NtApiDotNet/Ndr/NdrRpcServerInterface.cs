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
using System.Runtime.InteropServices;

namespace NtApiDotNet.Ndr
{
    /// <summary>
    /// A parsed NDR RPC_SERVER_INTERFACE structure.
    /// </summary>
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

        /// <summary>
        /// Resolve the local binding string for this service from the local Endpoint Mapper.
        /// </summary>
        /// <remarks>This only will return a valid value if the service is running and registered with the Endpoint Mapper. It can also hang.</remarks>
        /// <returns>The RPC binding string. Empty string if it doesn't exist or the lookup failed.</returns>
        public string ResolveLocalBindingString()
        {
            IntPtr binding = IntPtr.Zero;
            IntPtr str_binding = IntPtr.Zero;
            try
            {
                int result = NdrNativeUtils.RpcBindingFromStringBinding("ncalrpc:", out binding);
                if (result != 0)
                {
                    return string.Empty;
                }

                RPC_SERVER_INTERFACE ifspec = new RPC_SERVER_INTERFACE();
                ifspec.Length = Marshal.SizeOf(ifspec);
                ifspec.InterfaceId.SyntaxGUID = InterfaceId;
                ifspec.InterfaceId.SyntaxVersion = InterfaceVersion.ToRpcVersion();
                ifspec.TransferSyntax.SyntaxGUID = TransferSyntaxId;
                ifspec.TransferSyntax.SyntaxVersion = TransferSyntaxVersion.ToRpcVersion();

                result = NdrNativeUtils.RpcEpResolveBinding(binding, ref ifspec);
                if (result != 0)
                {
                    return string.Empty;
                }

                result = NdrNativeUtils.RpcBindingToStringBinding(binding, out str_binding);
                if (result != 0)
                {
                    return string.Empty;
                }

                return Marshal.PtrToStringUni(str_binding);
            }
            finally
            {
                if (binding != IntPtr.Zero)
                {
                    NdrNativeUtils.RpcBindingFree(ref binding);
                }
                if (str_binding != IntPtr.Zero)
                {
                    NdrNativeUtils.RpcStringFree(ref str_binding);
                }
            }
        }

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
            builder.AppendLine("[uuid(\"{0}\")]", InterfaceId);
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
    }
}
