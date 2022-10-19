//  Copyright 2022 Google LLC. All Rights Reserved.
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

using NtApiDotNet.Utilities.ASN1;
using NtApiDotNet.Utilities.ASN1.Builder;
using NtApiDotNet.Win32.Security.Buffers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.CredSSP
{
    /*
     TSRequest ::= SEQUENCE {
         version    [0] INTEGER,
         negoTokens [1] NegoData  OPTIONAL,
         authInfo   [2] OCTET STRING OPTIONAL,
         pubKeyAuth [3] OCTET STRING OPTIONAL,
         errorCode  [4] INTEGER OPTIONAL,
         clientNonce [5] OCTET STRING OPTIONAL
    }
    */

    /// <summary>
    /// Class to represent an authentication token for TSSSP.
    /// </summary>
    public sealed class TSAuthenticationToken : ASN1AuthenticationToken
    {
        #region Private Members
        private TSAuthenticationToken(byte[] data, DERValue[] values) : base(data, values)
        {
        }

        private static AuthenticationToken ParseNegoData(DERValue value, bool client)
        {
            if (!value.CheckSequence())
                throw new InvalidDataException();
            foreach (var next in value.Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    throw new InvalidDataException();
                switch (next.Tag)
                {
                    case 0:
                        return Parse(AuthenticationPackage.NEGOSSP_NAME, client, next.ReadChildOctetString());
                }
            }
            throw new InvalidDataException();
        }

        private class NegoData : IDERObject
        {
            private readonly byte[] _data;

            public NegoData(AuthenticationToken token)
            {
                _data = token.ToArray();
            }

            void IDERObject.Write(DERBuilder builder)
            {
                using (var seq = builder.CreateSequence())
                {
                    seq.WriteContextSpecific(0, _data);
                }
            }
        }
        #endregion

        #region Public Members
        /// <summary>
        /// Version of the TSRequest.
        /// </summary>
        public int Version { get; private set; }
        /// <summary>
        /// List of SPNEGO tokens.
        /// </summary>
        public IReadOnlyList<AuthenticationToken> NegoTokens { get; private set; }
        /// <summary>
        /// Encrypted authentication information.
        /// </summary>
        public byte[] AuthInfo { get; private set; }
        /// <summary>
        /// Encrypted public key information.
        /// </summary>
        public byte[] PublicKeyAuth { get; private set; }
        /// <summary>
        /// Error code if the SPNEGO authentication failed.
        /// </summary>
        public NtStatus? ErrorCode { get; private set; }
        /// <summary>
        /// Client nonce.
        /// </summary>
        public byte[] ClientNonce { get; private set; }
        #endregion

        #region Public Static Methods
        /// <summary>
        /// Parse bytes into a TSSSP token.
        /// </summary>
        /// <param name="data">The TSSSP token in bytes.</param>
        /// <returns>The TSSSP token.</returns>
        public static TSAuthenticationToken Parse(byte[] data)
        {
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            if (!TryParse(data, 0, false, out TSAuthenticationToken token))
            {
                throw new ArgumentException(nameof(data));
            }
            return token;
        }

        /// <summary>
        /// Create a TSSSP authentication token.
        /// </summary>
        /// <param name="version">The version number.</param>
        /// <param name="nego_tokens">List of authentication tokens.</param>
        /// <param name="auth_info">Encrypted authentication info.</param>
        /// <param name="public_key_auth">Encrypted public key authentication info.</param>
        /// <param name="error_code">Error code.</param>
        /// <param name="client_nonce">The client nonce.</param>
        /// <returns>The TSSSP authentication token.</returns>
        public static TSAuthenticationToken Create(int version, IEnumerable<AuthenticationToken> nego_tokens = null,
            byte[] auth_info = null, byte[] public_key_auth = null, NtStatus? error_code = null, byte[] client_nonce = null)
        {
            DERBuilder builder = new DERBuilder();
            using (var seq = builder.CreateSequence())
            {
                int? error_code_int = null;
                if (error_code.HasValue)
                {
                    error_code_int = (int)error_code.Value;
                }

                seq.WriteContextSpecific(0, version);
                seq.WriteContextSpecific(1, nego_tokens?.Select(t => new NegoData(t)));
                seq.WriteContextSpecific(2, auth_info);
                seq.WriteContextSpecific(3, public_key_auth);
                seq.WriteContextSpecific(4, error_code_int);
                seq.WriteContextSpecific(5, client_nonce);
            }
            return Parse(builder.ToArray());
        }

        /// <summary>
        /// Create a TSSSP authentication token with a single authentication token.
        /// </summary>
        /// <param name="version">The version number.</param>
        /// <param name="nego_token">The authentication tokens.</param>
        /// <returns>The TSSSP authentication token.</returns>
        public static TSAuthenticationToken Create(int version, AuthenticationToken nego_token)
        {
            if (nego_token is null)
            {
                throw new ArgumentNullException(nameof(nego_token));
            }
            return Create(version, new[] { nego_token });
        }

        /// <summary>
        /// Create a TSSSP authentication token with a single authentication token.
        /// </summary>
        /// <param name="version">The version number.</param>
        /// <param name="auth_context">The authentication context for the token.</param>
        /// <returns>The TSSSP authentication token.</returns>
        public static TSAuthenticationToken Create(int version, IAuthenticationContext auth_context)
        {
            return Create(version, auth_context?.Token);
        }

        /// <summary>
        /// Create a TSSSP authentication token from a certificate.
        /// </summary>
        /// <param name="version">The version number.</param>
        /// <param name="context">The authentication context for the encryption.</param>
        /// <param name="certificate">The certificate for generating public key values.</param>
        /// <param name="nonce">The client nonce.</param>
        /// <returns>The TSSSP authentication token.</returns>
        public static TSAuthenticationToken Create(int version, IAuthenticationContext context, X509Certificate certificate, byte[] nonce = null)
        {
            if (version < 5)
                throw new ArgumentException("Only support version 5 and above.", nameof(version));
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (certificate is null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            string magic;
            if (context is IClientAuthenticationContext)
            {
                magic = "CredSSP Client-To-Server Binding Hash\0";
            }
            else
            {
                magic = "CredSSP Server-To-Client Binding Hash\0";
            }

            System.Diagnostics.Debug.Assert(magic.Length == 0x26);

            if (nonce == null)
            {
                nonce = new byte[32];
                new Random().NextBytes(nonce);
            }
            else if (nonce.Length != 32)
            {
                throw new ArgumentException("Nonce must be 32 bytes in size.", nameof(nonce));
            }

            writer.Write(Encoding.ASCII.GetBytes(magic));
            writer.Write(nonce);
            writer.Write(certificate.GetPublicKey());

            var hash = EncryptData(context, SHA256.Create().ComputeHash(stm.ToArray()));

            AuthenticationToken[] tokens = null;
            if (!context.Token.IsEmpty)
                tokens = new[] { context.Token };

            return Create(version, public_key_auth: hash, client_nonce: nonce, nego_tokens: tokens);
        }

        /// <summary>
        /// Create a TSSSP authentication token with credentials.
        /// </summary>
        /// <param name="version">The version number.</param>
        /// <param name="context">The authentication context for the encryption.</param>
        /// <param name="credentials">The credentials for the user.</param>
        /// <returns>The TSSSP authentication token.</returns>
        public static TSAuthenticationToken Create(int version, IClientAuthenticationContext context, TSCredentials credentials)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (credentials is null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            return Create(version, auth_info: EncryptData(context, credentials.ToArray()));
        }

        /// <summary>
        /// Decrypt a TSSSP data buffer.
        /// </summary>
        /// <param name="context">The authentication context.</param>
        /// <param name="data">The buffer to decrypt.</param>
        /// <returns>The decrypted data.</returns>
        public static byte[] DecryptData(IAuthenticationContext context, byte[] data)
        {
            List<SecurityBuffer> buffers = new List<SecurityBuffer>
            {
                new SecurityBufferInOut(SecurityBufferType.Stream, data),
                new SecurityBufferOut(SecurityBufferType.Data, 0)
            };

            context.DecryptMessageNoSignature(buffers, 0);

            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            foreach (var buffer in buffers)
            {
                if (buffer.Type == SecurityBufferType.Data)
                {
                    writer.Write(buffer.ToArray());
                }
            }
            return stm.ToArray();
        }

        /// <summary>
        /// Encrypt a TSSSP data buffer.
        /// </summary>
        /// <param name="context">The authentication context.</param>
        /// <param name="data">The buffer to encrypt.</param>
        /// <returns>The encrypted data.</returns>
        public static byte[] EncryptData(IAuthenticationContext context, byte[] data)
        {
            List<SecurityBuffer> buffers = new List<SecurityBuffer>
            {
                new SecurityBufferOut(SecurityBufferType.Token, context.SecurityTrailerSize),
                new SecurityBufferInOut(SecurityBufferType.Data, data),
                new SecurityBufferOut(SecurityBufferType.Padding, 16)
            };

            context.EncryptMessageNoSignature(buffers, 0, 0);

            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            foreach (var buffer in buffers)
            {
                writer.Write(buffer.ToArray());
            }
            return stm.ToArray();
        }

        #endregion

        #region Public Methods
        /// <summary>
        /// Format the Authentication Token.
        /// </summary>
        /// <returns>The Formatted Token.</returns>
        public override string Format()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine($"<TSSSP Version {Version}>");
            if (NegoTokens?.Count > 0)
            {
                for (int i = 0; i < NegoTokens.Count; ++i)
                {
                    builder.AppendLine($"<NegoToken {i}>");
                    builder.Append(NegoTokens[i].Format());
                    builder.AppendLine($"</NegoToken>");
                }
            }

            if (AuthInfo?.Length > 0)
            {
                builder.AppendLine($"Auth Info       : {BitConverter.ToString(AuthInfo)}");
            }

            if (PublicKeyAuth?.Length > 0)
            {
                builder.AppendLine($"Public Key Auth : {BitConverter.ToString(PublicKeyAuth)}");
            }

            if (ClientNonce?.Length > 0)
            {
                builder.AppendLine($"Client Nonce    : {BitConverter.ToString(ClientNonce)}");
            }

            if (ErrorCode.HasValue)
            {
                builder.AppendLine($"Error Code      : {ErrorCode}");
            }
            builder.AppendLine("</TSSSP>");
            return builder.ToString();
        }
        #endregion

        #region Internal Static Methods
        internal static bool TryParse(byte[] data, int token_count, bool client, out TSAuthenticationToken token)
        {
            token = null;
            try
            {
                var values = DERParser.ParseData(data, 0);
                if (!values.CheckValueSequence())
                    throw new InvalidDataException();

                token = new TSAuthenticationToken(data, values);
                foreach (var next in values[0].Children)
                {
                    if (next.Type != DERTagType.ContextSpecific)
                        throw new InvalidDataException();
                    switch (next.Tag)
                    {
                        case 0:
                            token.Version = next.ReadChildInteger();
                            break;
                        case 1:
                            token.NegoTokens = next.ReadChildSequence(v => ParseNegoData(v, client)).AsReadOnly();
                            break;
                        case 2:
                            token.AuthInfo = next.ReadChildOctetString();
                            break;
                        case 3:
                            token.PublicKeyAuth = next.ReadChildOctetString();
                            break;
                        case 4:
                            token.ErrorCode = (NtStatus)next.ReadChildInteger();
                            break;
                        case 5:
                            token.ClientNonce = next.ReadChildOctetString();
                            break;
                        default:
                            throw new InvalidDataException();
                    }
                }

                return true;
            }
            catch
            {
                return false;
            }
        }
        #endregion
    }
}
