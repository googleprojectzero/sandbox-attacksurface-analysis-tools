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
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Class to represent a server authentication context.
    /// </summary>
    public sealed class ServerAuthenticationContext : IDisposable, IAuthenticationContext, IServerAuthenticationContext
    {
        private readonly CredentialHandle _creds;
        private readonly AcceptContextReqFlags _req_flags;
        private readonly SecDataRep _data_rep;
        private readonly byte[] _channel_binding;
        private SecHandle _context;
        private int _token_count;

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
        public AcceptContextRetFlags Flags { get; private set; }

        /// <summary>
        /// Expiry of the authentication.
        /// </summary>
        public long Expiry { get; private set; }

        /// <summary>
        /// Get the client name supplied by the Client.
        /// </summary>
        public string ClientTargetName => GetTargetName();

        /// <summary>
        /// Get the Session Key for this context.
        /// </summary>
        public byte[] SessionKey => SecurityContextUtils.GetSessionKey(_context);

        /// <summary>
        /// Get the maximum signature size of this context.
        /// </summary>
        public int MaxSignatureSize => SecurityContextUtils.GetMaxSignatureSize(_context);

        /// <summary>
        /// Get the size of the security trailer for this context.
        /// </summary>
        public int SecurityTrailerSize => SecurityContextUtils.GetSecurityTrailerSize(_context);

        /// <summary>
        /// Get the name of the authentication package.
        /// </summary>
        public string PackageName => SecurityContextUtils.GetPackageName(_context) ?? _creds.PackageName;

        /// <summary>
        /// Get an access token for the authenticated user.
        /// </summary>
        /// <returns>The user's access token.</returns>
        public NtToken GetAccessToken()
        {
            SecurityNativeMethods.QuerySecurityContextToken(_context, out SafeKernelObjectHandle token).CheckResult();
            return NtToken.FromHandle(token);
        }

        /// <summary>
        /// Impersonate the security context.
        /// </summary>
        /// <returns>The disposable context to revert the impersonation.</returns>
        public AuthenticationImpersonationContext Impersonate()
        {
            SecurityNativeMethods.ImpersonateSecurityContext(_context).CheckResult();
            return new AuthenticationImpersonationContext(_context);
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="creds">Credential handle.</param>
        /// <param name="req_attributes">Request attribute flags.</param>
        /// <param name="channel_binding">Optional channel binding token.</param>
        /// <param name="data_rep">Data representation.</param>
        public ServerAuthenticationContext(CredentialHandle creds, AcceptContextReqFlags req_attributes,
            byte[] channel_binding, SecDataRep data_rep)
        {
            _creds = creds;
            _req_flags = req_attributes & ~AcceptContextReqFlags.AllocateMemory;
            _data_rep = data_rep;
            _token_count = 0;
            _channel_binding = channel_binding;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="creds">Credential handle.</param>
        /// <param name="req_attributes">Request attribute flags.</param>
        /// <param name="data_rep">Data representation.</param>
        public ServerAuthenticationContext(CredentialHandle creds, 
            AcceptContextReqFlags req_attributes, SecDataRep data_rep)
            : this(creds, req_attributes, null, data_rep)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="creds">Credential handle.</param>
        public ServerAuthenticationContext(CredentialHandle creds) 
            : this(creds, AcceptContextReqFlags.None, SecDataRep.Native)
        {
        }

        /// <summary>
        /// Continue the authentication with the client token.
        /// </summary>
        /// <param name="token">The client token to continue authentication.</param>
        public void Continue(AuthenticationToken token)
        {
            Done = GenServerContext(token);
        }

        /// <summary>
        /// Make a signature for this context.
        /// </summary>
        /// <param name="messages">The message buffers to sign.</param>
        /// <param name="sequence_no">The sequence number.</param>
        /// <returns>The signature blob.</returns>
        public byte[] MakeSignature(IEnumerable<SecurityBuffer> messages, int sequence_no)
        {
            return SecurityContextUtils.MakeSignature(_context, 0, messages, sequence_no);
        }

        /// <summary>
        /// Make a signature for this context.
        /// </summary>
        /// <param name="message">The message to sign.</param>
        /// <param name="sequence_no">The sequence number.</param>
        /// <returns>The signature blob.</returns>
        public byte[] MakeSignature(byte[] message, int sequence_no)
        {
            return SecurityContextUtils.MakeSignature(_context, 0, message, sequence_no);
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
            return SecurityContextUtils.VerifySignature(_context, message, signature, sequence_no);
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
            return SecurityContextUtils.VerifySignature(_context, messages, signature, sequence_no);
        }

        /// <summary>
        /// Encrypt a message for this context.
        /// </summary>
        /// <param name="message">The message to encrypt.</param>
        /// <param name="sequence_no">The sequence number.</param>
        /// <returns>The encrypted message.</returns>
        public EncryptedMessage EncryptMessage(byte[] message, int sequence_no)
        {
            return SecurityContextUtils.EncryptMessage(_context, 0, message, sequence_no);
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
            return SecurityContextUtils.EncryptMessage(_context, 0, messages, sequence_no);
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
            SecurityContextUtils.DecryptMessage(_context, messages, signature, sequence_no);
        }

        /// <summary>
        /// Decrypt a message for this context.
        /// </summary>
        /// <param name="message">The message to decrypt.</param>
        /// <param name="sequence_no">The sequence number.</param>
        /// <returns>The decrypted message.</returns>
        public byte[] DecryptMessage(EncryptedMessage message, int sequence_no)
        {
            return SecurityContextUtils.DecryptMessage(_context, message, sequence_no);
        }

        /// <summary>
        /// Query the context's package info.
        /// </summary>
        /// <returns>The authentication package info,</returns>
        public AuthenticationPackage GetAuthenticationPackage()
        {
            return SecurityContextUtils.GetAuthenticationPackage(_context);
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
        /// Export the security context.
        /// </summary>
        /// <returns>The exported security context.</returns>
        public ExportedSecurityContext Export()
        {
            return SecurityContextUtils.ExportContext(_context, SecPkgContextExportFlags.None, _creds.PackageName);
        }

        private bool GenServerContext(AuthenticationToken token)
        {
            var token_buffer = new SecurityBufferOut(SecurityBufferType.Token, 64 * 1024);
            var output_buffers = new[] { token_buffer };
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
            SecStatusCode result = SecurityContextUtils.AcceptSecurityContext(_creds, _context,
                _req_flags, _data_rep, input_buffers, new_context, output_buffers, 
                out AcceptContextRetFlags context_attr, expiry).CheckResult();
            _context = new_context;
            Flags = context_attr;
            Expiry = expiry.QuadPart;

            Token = AuthenticationToken.Parse(_creds.PackageName, _token_count++, false, token_buffer.ToArray());
            return !(result == SecStatusCode.ContinueNeeded || result == SecStatusCode.CompleteAndContinue);
        }

        private void Dispose(bool _)
        {
            if (_context != null)
            {
                SecurityNativeMethods.DeleteSecurityContext(_context);
            }
        }

        /// <summary>
        /// Finalizer.
        /// </summary>
        ~ServerAuthenticationContext()
        {
            Dispose(false);
        }

        private string GetTargetName()
        {
            using (var buffer = new SafeStructureInOutBuffer<SecPkgContext_ClientSpecifiedTarget>())
            {
                var result = SecurityNativeMethods.QueryContextAttributesEx(_context, SECPKG_ATTR.CLIENT_SPECIFIED_TARGET, buffer, buffer.Length);
                if (result == SecStatusCode.Success)
                    return Marshal.PtrToStringUni(buffer.Result.sTargetName);
            }
            return string.Empty;
        }
    }
}
