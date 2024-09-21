//  Copyright 2021 Google LLC. All Rights Reserved.
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

using NtApiDotNet.Win32.Rpc.Transport.PDU;
using NtApiDotNet.Win32.Security.Authentication;
using NtApiDotNet.Win32.Security.Buffers;
using System;
using System.Collections.Generic;
using System.IO;

namespace NtApiDotNet.Win32.Rpc.Transport
{
    /// <summary>
    /// Class to represent an RPC transport security context.
    /// </summary>
    public sealed class RpcTransportSecurityContext
    {
        private readonly IRpcClientTransport _client_transport;

        /// <summary>
        /// The ID of the security context.
        /// </summary>
        public int ContextId { get; }
        /// <summary>
        /// The RPC transport security settings.
        /// </summary>
        public RpcTransportSecurity TransportSecurity { get; }
        /// <summary>
        /// The authentication context.
        /// </summary>
        public IClientAuthenticationContext AuthContext { get; }
        /// <summary>
        /// The negotiated authentication type.
        /// </summary>
        public RpcAuthenticationType NegotiatedAuthType { get; private set; }
        /// <summary>
        /// The authentication level.
        /// </summary>
        public RpcAuthenticationLevel AuthenticationLevel => TransportSecurity.AuthenticationLevel;

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The object as a string.</returns>
        public override string ToString()
        {
            return $"Context ID: {ContextId} - Type: {NegotiatedAuthType} - Level: {AuthenticationLevel}";
        }

        internal bool Authenticated => AuthContext?.Done ?? false;

        internal int AuthDataLength
        {
            get
            {
                switch (TransportSecurity.AuthenticationLevel)
                {
                    case RpcAuthenticationLevel.PacketIntegrity:
                        return AuthContext.MaxSignatureSize;
                    case RpcAuthenticationLevel.PacketPrivacy:
                        return AuthContext.SecurityTrailerSize;
                    default:
                        return 0;
                }
            }
        }

        internal int MaxAuthLegs => TransportSecurity.AuthenticationType == RpcAuthenticationType.WinNT ? 3 : 8;

        internal void SetNegotiatedAuthType()
        {
            if (TransportSecurity.AuthenticationType == RpcAuthenticationType.Negotiate)
            {
                var package_name = AuthContext.PackageName;
                NegotiatedAuthType = AuthenticationPackage.CheckKerberos(package_name)
                    ? RpcAuthenticationType.Kerberos : RpcAuthenticationType.WinNT;
            }
            else
            {
                NegotiatedAuthType = TransportSecurity.AuthenticationType;
            }
        }

        internal RpcTransportSecurityContext Check(IRpcClientTransport client_transport)
        {
            if (client_transport != _client_transport)
            {
                throw new ArgumentException("Security context wasn't created by this RPC transport.");
            }
            return this;
        }

        internal RpcTransportSecurityContext(IRpcClientTransport client_transport, 
            RpcTransportSecurity transport_security, int context_id)
        {
            _client_transport = client_transport;
            ContextId = context_id;
            TransportSecurity = transport_security;
            AuthContext = transport_security.CreateClientContext();
        }

        internal byte[] ProtectPDU(byte[] header, ref byte[] stub_data, int auth_padding_length, int send_sequence_no)
        {
            List<SecurityBuffer> buffers = new List<SecurityBuffer>();
            buffers.Add(new SecurityBufferInOut(SecurityBufferType.Data | SecurityBufferType.ReadOnly, header));
            var stub_data_buffer = new SecurityBufferInOut(SecurityBufferType.Data, stub_data);
            buffers.Add(stub_data_buffer);
            buffers.Add(new SecurityBufferInOut(SecurityBufferType.Data | SecurityBufferType.ReadOnly,
                AuthData.ToArray(TransportSecurity, auth_padding_length, ContextId, new byte[0])));

            byte[] signature = new byte[0];
            if (TransportSecurity.AuthenticationLevel == RpcAuthenticationLevel.PacketIntegrity)
            {
                signature = AuthContext.MakeSignature(buffers, send_sequence_no);
            }
            else if (TransportSecurity.AuthenticationLevel == RpcAuthenticationLevel.PacketPrivacy)
            {
                signature = AuthContext.EncryptMessage(buffers, SecurityQualityOfProtectionFlags.None, send_sequence_no);
                stub_data = stub_data_buffer.ToArray();
                RpcUtils.DumpBuffer(true, "Send Encrypted Data", stub_data);
            }

            if (signature.Length > 0)
            {
                RpcUtils.DumpBuffer(true, "Send Signature Data", signature);
            }

            return AuthData.ToArray(TransportSecurity, auth_padding_length, ContextId, signature);
        }

        internal byte[] UnprotectPDU(byte[] header, byte[] stub_data, AuthData auth_data, int recv_sequence_no)
        {
            List<SecurityBuffer> buffers = new List<SecurityBuffer>();
            buffers.Add(new SecurityBufferInOut(SecurityBufferType.Data | SecurityBufferType.ReadOnly, header));
            var stub_data_buffer = new SecurityBufferInOut(SecurityBufferType.Data, stub_data);
            buffers.Add(stub_data_buffer);
            byte[] signature = auth_data.Data;
            auth_data.Data = new byte[0];
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            auth_data.Write(writer, auth_data.Padding);

            buffers.Add(new SecurityBufferInOut(SecurityBufferType.Data | SecurityBufferType.ReadOnly, stm.ToArray()));

            if (TransportSecurity.AuthenticationLevel == RpcAuthenticationLevel.PacketIntegrity)
            {
                if (!AuthContext.VerifySignature(buffers, signature, recv_sequence_no))
                {
                    throw new RpcTransportException("Invalid response PDU signature.");
                }
            }
            else if (TransportSecurity.AuthenticationLevel == RpcAuthenticationLevel.PacketPrivacy)
            {
                AuthContext.DecryptMessage(buffers, signature, recv_sequence_no);
                stub_data = stub_data_buffer.ToArray();
            }
            else
            {
                // Do nothing.
            }

            Array.Resize(ref stub_data, stub_data.Length - auth_data.Padding);

            return stub_data;
        }
    }
}
