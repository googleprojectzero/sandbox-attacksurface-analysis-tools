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

using NtApiDotNet.Win32.Security.Authentication.Kerberos.Client;
using NtApiDotNet.Win32.Security.Authentication.Ntlm.Client;
using NtApiDotNet.Win32.Security.Buffers;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace NtApiDotNet.Win32.Security.Authentication.Negotiate.Client
{
    /// <summary>
    /// Client authentication context for Negotiate.
    /// </summary>
    /// <remarks>This is only a wrapper around a single managed client context without the real SPNEGO tokens. 
    /// This works because the SSPI server context will fall back to the low-level package if the initial token matches 
    /// what's expected.</remarks>
    public sealed class NegotiateClientAuthenticationContext : IClientAuthenticationContext
    {
        #region Private Members
        private readonly IClientAuthenticationContext _client_context;
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="credentials">The user's credentials.</param>
        /// <param name="target_name">The target name for the authentication.</param>
        /// <param name="config">Additional configuration for the authentication context.</param>
        /// <param name="request_attributes">Request attributes for the context.</param>
        /// <param name="initialize">True to initialize the security context.</param>
        public NegotiateClientAuthenticationContext(AuthenticationCredentials credentials, InitializeContextReqFlags request_attributes,
            string target_name = null, NegotiateClientAuthenticationContextConfig config = null, bool initialize = true)
        {
            if (credentials is IKerberosAuthenticationCredentials)
            {
                var kerb_config = new KerberosClientAuthenticationContextConfig()
                {
                    ChannelBinding = config?.ChannelBinding
                };

                _client_context = new KerberosClientAuthenticationContext(credentials, target_name, request_attributes, kerb_config, initialize);
            }
            else
            {
                var ntlm_config = new NtlmClientAuthenticationContextConfig()
                {
                    ChannelBinding = config?.ChannelBinding
                };
                _client_context = new NtlmClientAuthenticationContext(credentials, request_attributes, target_name, ntlm_config, initialize);
            }
        }
        #endregion

        #region IClientAuthenticationContext Implementation
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        public SecPkgLastClientTokenStatus LastTokenStatus => Done ? SecPkgLastClientTokenStatus.Yes : SecPkgLastClientTokenStatus.No;

        public InitializeContextReqFlags RequestAttributes => _client_context.RequestAttributes;

        public InitializeContextRetFlags ReturnAttributes => _client_context.ReturnAttributes;

        public AuthenticationToken Token => _client_context.Token;

        public bool Done => _client_context.Done;

        public long Expiry => _client_context.Expiry;

        public byte[] SessionKey => _client_context.SessionKey;

        public string PackageName => Done ? _client_context.PackageName : AuthenticationPackage.NEGOSSP_NAME;

        public int MaxSignatureSize => _client_context.MaxSignatureSize;

        public int SecurityTrailerSize => _client_context.SecurityTrailerSize;

        public X509Certificate2 LocalCertificate => null;

        public X509Certificate2 RemoteCertificate => null;

        public int StreamHeaderSize => 0;

        public int StreamTrailerSize => 0;

        public int StreamBufferCount => 0;

        public int StreamMaxMessageSize => 0;

        public int StreamBlockSize => 0;

        public void Continue(AuthenticationToken token)
        {
            _client_context.Continue(token);
        }

        public void Continue(AuthenticationToken token, IEnumerable<SecurityBuffer> additional_input)
        {
            _client_context.Continue(token, additional_input);
        }

        public void Continue(AuthenticationToken token, IEnumerable<SecurityBuffer> additional_input, IEnumerable<SecurityBuffer> additional_output)
        {
            _client_context.Continue(token, additional_input, additional_output);
        }

        public void Continue(IEnumerable<SecurityBuffer> input_buffers, IEnumerable<SecurityBuffer> additional_output)
        {
            _client_context.Continue(input_buffers, additional_output);
        }

        public void Continue()
        {
            _client_context.Continue();
        }

        public byte[] DecryptMessage(EncryptedMessage message, int sequence_no)
        {
            return _client_context.DecryptMessage(message, sequence_no);
        }

        public void DecryptMessage(IEnumerable<SecurityBuffer> messages, byte[] signature, int sequence_no)
        {
            _client_context.DecryptMessage(messages, signature, sequence_no);
        }

        public void DecryptMessageNoSignature(IEnumerable<SecurityBuffer> messages, int sequence_no)
        {
            _client_context.DecryptMessageNoSignature(messages, sequence_no);
        }

        public void Dispose()
        {
            _client_context.Dispose();
        }

        public EncryptedMessage EncryptMessage(byte[] message, SecurityQualityOfProtectionFlags quality_of_protection, int sequence_no)
        {
            return _client_context.EncryptMessage(message, quality_of_protection, sequence_no);
        }

        public byte[] EncryptMessage(IEnumerable<SecurityBuffer> messages, SecurityQualityOfProtectionFlags quality_of_protection, int sequence_no)
        {
            return _client_context.EncryptMessage(messages, quality_of_protection, sequence_no);
        }

        public void EncryptMessageNoSignature(IEnumerable<SecurityBuffer> messages, SecurityQualityOfProtectionFlags quality_of_protection, int sequence_no)
        {
            _client_context.EncryptMessageNoSignature(messages, quality_of_protection, sequence_no);
        }

        public ExportedSecurityContext Export()
        {
            throw new NotImplementedException();
        }

        public AuthenticationPackage GetAuthenticationPackage()
        {
            return _client_context.GetAuthenticationPackage();
        }

        public byte[] MakeSignature(byte[] message, int sequence_no)
        {
            return _client_context.MakeSignature(message, sequence_no);
        }

        public byte[] MakeSignature(IEnumerable<SecurityBuffer> messages, int sequence_no)
        {
            return _client_context.MakeSignature(messages, sequence_no);
        }

        public bool VerifySignature(byte[] message, byte[] signature, int sequence_no)
        {
            return _client_context.VerifySignature(message, signature, sequence_no);
        }

        public bool VerifySignature(IEnumerable<SecurityBuffer> messages, byte[] signature, int sequence_no)
        {
            return _client_context.VerifySignature(messages, signature, sequence_no);
        }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
        #endregion
    }
}
