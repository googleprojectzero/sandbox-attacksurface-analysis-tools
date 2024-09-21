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

using NtApiDotNet.Win32.Security.Buffers;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace NtApiDotNet.Win32.Security.Authentication.CredSSP.Client
{
    /// <summary>
    /// Class to implement a TSSSP client authentication context.
    /// </summary>
    public sealed class TSSSPClientAuthenticationContext : IClientAuthenticationContext
    {
        #region Private Members
        private readonly IClientAuthenticationContext _client_ctx;
        private readonly TSCredentials _delegate_creds;
        private readonly X509Certificate _certificate;

        private static X509Certificate GetCertificate(IEnumerable<SecurityBuffer> additional_input)
        {
            return additional_input?.OfType<SecurityBufferTSSSPCertificate>().Select(c => c.Certificate).FirstOrDefault();
        }

        private void ContinueInternal(byte[] token, X509Certificate certificate)
        {
            if (Token == null)
            {
                Token = TSAuthenticationToken.Create(6, _client_ctx);
                return;
            }

            if (!_client_ctx.Done)
            {
                var ts_token = TSAuthenticationToken.Parse(token);
                if (ts_token.NegoTokens.IsEmpty())
                    throw new ArgumentException("Missing inner authentication token.", nameof(token));

                _client_ctx.Continue(ts_token.NegoTokens[0]);
                if (_client_ctx.Done)
                    Token = TSAuthenticationToken.Create(6, _client_ctx, certificate ?? _certificate);
                else
                    Token = TSAuthenticationToken.Create(6, _client_ctx);
            }
            else if (!Done)
            {
                _ = TSAuthenticationToken.Parse(token);
                Token = TSAuthenticationToken.Create(6, _client_ctx, _delegate_creds);
                Done = true;
            }
            else
            {
                Token = new AuthenticationToken();
            }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="context">The client authentication context for the inner authentication.</param>
        /// <param name="certificate">Certificate for the outer TLS wrapper. Can be null but then must pass in the certificating using the SecurityBufferTSSSPCertificate buffer.</param>
        /// <param name="delegate_creds">The credentials to delegate.</param>
        /// <param name="initialize">Specify to initialize the context.</param>
        public TSSSPClientAuthenticationContext(IClientAuthenticationContext context, TSCredentials delegate_creds, X509Certificate certificate = null, bool initialize = true)
        {
            _client_ctx = context ?? throw new ArgumentNullException(nameof(context));
            _delegate_creds = delegate_creds ?? throw new ArgumentNullException(nameof(delegate_creds));
            _certificate = certificate;
            if (initialize)
            {
                ContinueInternal(null, null);
            }
        }
        #endregion

        #region IClientAuthenticationContext Implementation
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        public SecPkgLastClientTokenStatus LastTokenStatus => Done ? SecPkgLastClientTokenStatus.Yes : SecPkgLastClientTokenStatus.No;

        public InitializeContextReqFlags RequestAttributes { get; }

        public InitializeContextRetFlags ReturnAttributes { get; private set; }

        public AuthenticationToken Token { get; private set; }

        public bool Done { get; private set; }

        public long Expiry => 0;

        public byte[] SessionKey => Array.Empty<byte>();

        public string PackageName => AuthenticationPackage.TSSSP_NAME;

        public int MaxSignatureSize => 0;

        public int SecurityTrailerSize => 0;

        public X509Certificate2 LocalCertificate => null;

        public X509Certificate2 RemoteCertificate => null;

        public int StreamHeaderSize => 0;

        public int StreamTrailerSize => 0;

        public int StreamBufferCount => 0;

        public int StreamMaxMessageSize => 0;

        public int StreamBlockSize => 0;

        public void Continue(AuthenticationToken token)
        {
            ContinueInternal(token?.ToArray(), null);
        }

        public void Continue(AuthenticationToken token, IEnumerable<SecurityBuffer> additional_input)
        {
            ContinueInternal(token?.ToArray(), GetCertificate(additional_input));
        }

        public void Continue(AuthenticationToken token, IEnumerable<SecurityBuffer> additional_input, IEnumerable<SecurityBuffer> additional_output)
        {
            ContinueInternal(token?.ToArray(), GetCertificate(additional_input));
        }

        public void Continue(IEnumerable<SecurityBuffer> input_buffers, IEnumerable<SecurityBuffer> additional_output)
        {
            var token_buffer = input_buffers?.FirstOrDefault(b => b.Type == SecurityBufferType.Token);
            ContinueInternal(token_buffer?.ToArray(), GetCertificate(input_buffers));
        }

        public void Continue()
        {
            ContinueInternal(null, null);
        }

        public byte[] DecryptMessage(EncryptedMessage message, int sequence_no)
        {
            throw new NotImplementedException();
        }

        public void DecryptMessage(IEnumerable<SecurityBuffer> messages, byte[] signature, int sequence_no)
        {
            throw new NotImplementedException();
        }

        public void DecryptMessageNoSignature(IEnumerable<SecurityBuffer> messages, int sequence_no)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
        }

        public EncryptedMessage EncryptMessage(byte[] message, SecurityQualityOfProtectionFlags quality_of_protection, int sequence_no)
        {
            throw new NotImplementedException();
        }

        public byte[] EncryptMessage(IEnumerable<SecurityBuffer> messages, SecurityQualityOfProtectionFlags quality_of_protection, int sequence_no)
        {
            throw new NotImplementedException();
        }

        public void EncryptMessageNoSignature(IEnumerable<SecurityBuffer> messages, SecurityQualityOfProtectionFlags quality_of_protection, int sequence_no)
        {
            throw new NotImplementedException();
        }

        public ExportedSecurityContext Export()
        {
            throw new NotImplementedException();
        }

        public AuthenticationPackage GetAuthenticationPackage()
        {
            throw new NotImplementedException();
        }

        public byte[] MakeSignature(byte[] message, int sequence_no)
        {
            throw new NotImplementedException();
        }

        public byte[] MakeSignature(IEnumerable<SecurityBuffer> messages, int sequence_no)
        {
            throw new NotImplementedException();
        }

        public bool VerifySignature(byte[] message, byte[] signature, int sequence_no)
        {
            throw new NotImplementedException();
        }

        public bool VerifySignature(IEnumerable<SecurityBuffer> messages, byte[] signature, int sequence_no)
        {
            throw new NotImplementedException();
        }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
        #endregion
    }
}
