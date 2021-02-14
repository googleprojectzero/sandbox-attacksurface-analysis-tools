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

using NtApiDotNet.Win32.Security.Buffers;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Class to represent a client authentication context.
    /// </summary>
    public sealed class ClientAuthenticationContext : IDisposable, IAuthenticationContext, IClientAuthenticationContext
    {
        private readonly CredentialHandle _creds;
        private readonly InitializeContextReqFlags _req_attributes;
        private readonly string _target;
        private readonly SecDataRep _data_rep;
        private readonly byte[] _channel_binding;
        private int _token_count;
        private SecHandle _context;

        /// <summary>
        /// The current authentication token.
        /// </summary>
        public AuthenticationToken Token { get; private set; }

        /// <summary>
        /// Whether the authentication is done.
        /// </summary>
        public bool Done { get; private set; }

        /// <summary>
        /// Current status flags.
        /// </summary>
        public InitializeContextRetFlags Flags { get; private set; }

        /// <summary>
        /// Expiry of the authentication.
        /// </summary>
        public long Expiry { get; private set; }

        /// <summary>
        /// Get the Session Key for this context.
        /// </summary>
        public byte[] SessionKey => SecurityContextUtils.GetSessionKey(Context);

        /// <summary>
        /// Get the maximum signature size of this context.
        /// </summary>
        public int MaxSignatureSize => SecurityContextUtils.GetMaxSignatureSize(Context);

        /// <summary>
        /// Get the size of the security trailer for this context.
        /// </summary>
        public int SecurityTrailerSize => SecurityContextUtils.GetSecurityTrailerSize(Context);

        /// <summary>
        /// Get the last token status for the client context.
        /// </summary>
        public SecPkgLastClientTokenStatus LastTokenStatus => 
            SecurityContextUtils.QueryContextAttribute<SecPkgContext_LastClientTokenStatus>(Context, 
            SECPKG_ATTR.LAST_CLIENT_TOKEN_STATUS).LastClientTokenStatus;

        internal SecHandle Context => _context ?? throw new InvalidOperationException("Client authentication context hasn't been initialized.");

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="creds">Credential handle.</param>
        /// <param name="req_attributes">Request attribute flags.</param>
        /// <param name="target">Target SPN (optional).</param>
        /// <param name="data_rep">Data representation.</param>
        /// <param name="channel_binding">Optional channel binding token.</param>
        public ClientAuthenticationContext(CredentialHandle creds, 
            InitializeContextReqFlags req_attributes,
            string target, byte[] channel_binding, SecDataRep data_rep)
        {
            _creds = creds;
            _req_attributes = req_attributes & ~InitializeContextReqFlags.AllocateMemory;
            _target = target == string.Empty ? null : target;
            _data_rep = data_rep;
            _token_count = 0;
            _channel_binding = channel_binding;
            Continue(null);
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="creds">Credential handle.</param>
        /// <param name="req_attributes">Request attribute flags.</param>
        /// <param name="target">Target SPN (optional).</param>
        /// <param name="data_rep">Data representation.</param>
        public ClientAuthenticationContext(CredentialHandle creds,
            InitializeContextReqFlags req_attributes,
            string target, SecDataRep data_rep)
            : this(creds, req_attributes, target, null, data_rep)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="creds">Credential handle.</param>
        /// <param name="req_attributes">Request attribute flags.</param>
        /// <param name="data_rep">Data representation.</param>
        public ClientAuthenticationContext(CredentialHandle creds, InitializeContextReqFlags req_attributes, SecDataRep data_rep)
            : this(creds, req_attributes, null, null, data_rep)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="creds">Credential handle.</param>
        public ClientAuthenticationContext(CredentialHandle creds)
            : this(creds, InitializeContextReqFlags.None, null, SecDataRep.Native)
        {
        }

        /// <summary>
        /// Continue the authentication with the server token.
        /// </summary>
        /// <param name="token">The server token to continue authentication.</param>
        public void Continue(AuthenticationToken token)
        {
            Done = GenClientContext(token);
        }

        /// <summary>
        /// Make a signature for this context.
        /// </summary>
        /// <param name="messages">The message buffers to sign.</param>
        /// <param name="sequence_no">The sequence number.</param>
        /// <returns>The signature blob.</returns>
        public byte[] MakeSignature(IEnumerable<SecurityBuffer> messages, int sequence_no)
        {
            return SecurityContextUtils.MakeSignature(Context, 0, messages, sequence_no);
        }

        /// <summary>
        /// Make a signature for this context.
        /// </summary>
        /// <param name="message">The message to sign.</param>
        /// <param name="sequence_no">The sequence number.</param>
        /// <returns>The signature blob.</returns>
        public byte[] MakeSignature(byte[] message, int sequence_no)
        {
            return SecurityContextUtils.MakeSignature(Context, 0, message, sequence_no);
        }

        /// <summary>
        /// Verify a signature for this context.
        /// </summary>
        /// <param name="message">The message to verify.</param>
        /// <param name="signature">The signature blob for the message.</param>
        /// <param name="sequence_no">The sequence number.</param>
        /// <returns>True if the signature is valid, otherwise false.</returns>
        public bool VerifySignature(byte[] message, byte[] signature, int sequence_no)
        {
            return SecurityContextUtils.VerifySignature(Context, message, signature, sequence_no);
        }

        /// <summary>
        /// Verify a signature for this context.
        /// </summary>
        /// <param name="messages">The messages to verify.</param>
        /// <param name="signature">The signature blob for the message.</param>
        /// <param name="sequence_no">The sequence number.</param>
        /// <returns>True if the signature is valid, otherwise false.</returns>
        public bool VerifySignature(IEnumerable<SecurityBuffer> messages, byte[] signature, int sequence_no)
        {
            return SecurityContextUtils.VerifySignature(Context, messages, signature, sequence_no);
        }

        /// <summary>
        /// Encrypt a message for this context.
        /// </summary>
        /// <param name="message">The message to encrypt.</param>
        /// <param name="sequence_no">The sequence number.</param>
        /// <returns>The encrypted message.</returns>
        public EncryptedMessage EncryptMessage(byte[] message, int sequence_no)
        {
            return SecurityContextUtils.EncryptMessage(Context, 0, message, sequence_no);
        }

        /// <summary>
        /// Encrypt a message for this context.
        /// </summary>
        /// <param name="messages">The messages to encrypt.</param>
        /// <param name="sequence_no">The sequence number.</param>
        /// <returns>The signature for the messages.</returns>
        /// <remarks>The messages are encrypted in place. You can add buffers with the ReadOnly flag to prevent them being encrypted.</remarks>
        public byte[] EncryptMessage(IEnumerable<SecurityBuffer> messages, int sequence_no)
        {
            return SecurityContextUtils.EncryptMessage(Context, 0, messages, sequence_no);
        }

        /// <summary>
        /// Decrypt a message for this context.
        /// </summary>
        /// <param name="message">The message to decrypt.</param>
        /// <param name="sequence_no">The sequence number.</param>
        /// <returns>The decrypted message.</returns>
        public byte[] DecryptMessage(EncryptedMessage message, int sequence_no)
        {
            return SecurityContextUtils.DecryptMessage(Context, message, sequence_no);
        }

        /// <summary>
        /// Decrypt a message for this context.
        /// </summary>
        /// <param name="messages">The messages to decrypt.</param>
        /// <param name="sequence_no">The sequence number.</param>
        /// <param name="signature">The signature for the messages.</param>
        /// <remarks>The messages are decrypted in place. You can add buffers with the ReadOnly flag to prevent them being decrypted.</remarks>
        public void DecryptMessage(IEnumerable<SecurityBuffer> messages, byte[] signature, int sequence_no)
        {
            SecurityContextUtils.DecryptMessage(Context, messages, signature, sequence_no);
        }

        /// <summary>
        /// Query the context's package info.
        /// </summary>
        /// <returns>The authentication package info,</returns>
        public AuthenticationPackage GetAuthenticationPackage()
        {
            return SecurityContextUtils.GetAuthenticationPackage(Context);
        }

        /// <summary>
        /// Get the name of the authentication package.
        /// </summary>
        public string PackageName => SecurityContextUtils.GetPackageName(Context) ?? _creds.PackageName;

        private bool GenClientContext(AuthenticationToken token)
        {
            var token_buffer = new SecurityBufferAllocMem(SecurityBufferType.Token);
            var output_buffers = new [] { token_buffer };
            var input_buffers = new List<SecurityBuffer>();

            if (token != null)
            {
                input_buffers.Add(new SecurityBufferInOut(SecurityBufferType.Token, token.ToArray()));
            }

            if (_channel_binding != null)
            {
                input_buffers.Add(new SecurityBufferChannelBinding(_channel_binding));
            }

            LargeInteger expiry = new LargeInteger();
            SecHandle new_context = _context ?? new SecHandle();
            SecStatusCode result = SecurityContextUtils.InitializeSecurityContext(_creds, _context, _target, 
                _req_attributes | InitializeContextReqFlags.AllocateMemory, _data_rep, input_buffers, new_context, 
                output_buffers, out InitializeContextRetFlags flags, expiry);
            _context = new_context;
            Expiry = expiry.QuadPart;
            Flags = flags & ~InitializeContextRetFlags.AllocatedMemory;
            Token = AuthenticationToken.Parse(_creds.PackageName, _token_count++, true, token_buffer.ToArray());
            return !(result == SecStatusCode.ContinueNeeded || result == SecStatusCode.CompleteAndContinue);
        }

        private void Dispose(bool _)
        {
            if (_context != null)
            {
                SecurityNativeMethods.DeleteSecurityContext(_context);
                _context = null;
            }
        }

        /// <summary>
        /// Dispose the client context.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Finalizer.
        /// </summary>
        ~ClientAuthenticationContext()
        {
            Dispose(false);
        }
    }
}
