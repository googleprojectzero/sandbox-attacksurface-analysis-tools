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
    /// Class to implement a CredSSP client authentication context.
    /// </summary>
    public sealed class CredSSPClientAuthenticationContext : IClientAuthenticationContext
    {
        #region Private Members
        private readonly IClientAuthenticationContext _schannel_ctx;
        private readonly IClientAuthenticationContext _tsssp_ctx;

        private AuthenticationToken EncryptBuffer(byte[] token)
        {
            List<SecurityBuffer> buffers = new List<SecurityBuffer>
            {
                new SecurityBufferOut(SecurityBufferType.StreamHeader, _schannel_ctx.StreamHeaderSize),
                new SecurityBufferInOut(SecurityBufferType.Data, token),
                new SecurityBufferOut(SecurityBufferType.StreamTrailer, _schannel_ctx.StreamTrailerSize),
                new SecurityBufferOut(SecurityBufferType.Empty, 0)
            };

            _schannel_ctx.EncryptMessageNoSignature(buffers, SecurityQualityOfProtectionFlags.None, 0);
            return new AuthenticationToken(buffers.SelectMany(b => b.ToArray()).ToArray());
        }

        private AuthenticationToken DecryptBuffer(byte[] buffer)
        {
            List<SecurityBuffer> buffers = new List<SecurityBuffer>
            {
                new SecurityBufferInOut(SecurityBufferType.Data, buffer),
                new SecurityBufferOut(SecurityBufferType.Empty, 0),
                new SecurityBufferOut(SecurityBufferType.Empty, 0),
                new SecurityBufferOut(SecurityBufferType.Empty, 0)
            };
            _schannel_ctx.DecryptMessageNoSignature(buffers, 0);
            return new AuthenticationToken(buffers.Where(b => b.Type == SecurityBufferType.Data).SelectMany(b => b.ToArray()).ToArray());
        }

        private void ContinueInternal(byte[] token)
        {
            if (Token == null)
            {
                Token = _schannel_ctx.Token;
                return;
            }

            if (!_schannel_ctx.Done)
            {
                _schannel_ctx.Continue(new AuthenticationToken(token));
                if (_schannel_ctx.Done)
                {
                    Token = EncryptBuffer(_tsssp_ctx.Token.ToArray());
                }
                else
                {
                    Token = _schannel_ctx.Token;
                }
            }
            else if (!_tsssp_ctx.Done)
            {
                var additional_input = new[] { new SecurityBufferTSSSPCertificate(_schannel_ctx.RemoteCertificate) };
                _tsssp_ctx.Continue(DecryptBuffer(token), additional_input);
                Token = EncryptBuffer(_tsssp_ctx.Token.ToArray());
            }
            else if (!Done)
            {
                _ = DecryptBuffer(token);
                Token = EncryptBuffer(_tsssp_ctx.Token.ToArray());
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
        /// <param name="hostname">Hostname for the SChannel connection.</param>
        /// <param name="tsssp_ctx">Inner TSSSP context.</param>
        public CredSSPClientAuthenticationContext(string hostname, IClientAuthenticationContext tsssp_ctx)
        {
            _schannel_ctx = AuthenticationPackage.CreateClient(AuthenticationPackage.SCHANNEL_NAME, null,
                InitializeContextReqFlags.Stream | InitializeContextReqFlags.Confidentiality | InitializeContextReqFlags.ManualCredValidation, hostname);
            _tsssp_ctx = tsssp_ctx;
            ContinueInternal(null);
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="hostname">Hostname for the SChannel connection.</param>
        /// <param name="nego_ctx">Inner authentication context.</param>
        /// <param name="delegate_creds">Credentials to delegate.</param>
        public CredSSPClientAuthenticationContext(string hostname, IClientAuthenticationContext nego_ctx, TSCredentials delegate_creds) :
            this(hostname, new TSSSPClientAuthenticationContext(nego_ctx, delegate_creds))
        {
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

        public string PackageName => AuthenticationPackage.CREDSSP_NAME;

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
            ContinueInternal(token?.ToArray());
        }

        public void Continue(AuthenticationToken token, IEnumerable<SecurityBuffer> additional_input)
        {
            ContinueInternal(token?.ToArray());
        }

        public void Continue(AuthenticationToken token, IEnumerable<SecurityBuffer> additional_input, IEnumerable<SecurityBuffer> additional_output)
        {
            ContinueInternal(token?.ToArray());
        }

        public void Continue(IEnumerable<SecurityBuffer> input_buffers, IEnumerable<SecurityBuffer> additional_output)
        {
            var token_buffer = input_buffers?.FirstOrDefault(b => b.Type == SecurityBufferType.Token);
            ContinueInternal(token_buffer?.ToArray());
        }

        public void Continue()
        {
            ContinueInternal(null);
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
            _schannel_ctx?.Dispose();
            _tsssp_ctx?.Dispose();
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
        #endregion
    }
}
