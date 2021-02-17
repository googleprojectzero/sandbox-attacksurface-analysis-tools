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
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Class to represent a server authentication context.
    /// </summary>
    public sealed class ServerAuthenticationContext : IDisposable, IAuthenticationContext, IServerAuthenticationContext
    {
        #region Private Members
        private readonly CredentialHandle _creds;
        private SecHandle _context;
        private int _token_count;

        private SecStatusCode CallAccept(List<SecurityBuffer> input_buffers, List<SecurityBuffer> output_buffers, bool throw_on_error)
        {
            var token_buffer = new SecurityBufferAllocMem(SecurityBufferType.Token);
            output_buffers.Insert(0, token_buffer);

            if (ChannelBinding != null)
            {
                input_buffers.Add(new SecurityBufferChannelBinding(ChannelBinding));
            }

            LargeInteger expiry = new LargeInteger();
            SecHandle new_context = _context ?? new SecHandle();
            SecStatusCode result = SecurityContextUtils.AcceptSecurityContext(_creds, _context,
                RequestAttributes | AcceptContextReqFlags.AllocateMemory, DataRepresentation, input_buffers, new_context, output_buffers,
                out AcceptContextRetFlags context_attr, expiry, throw_on_error);
            if (!result.IsSuccess())
                return result;
            _context = new_context;
            ReturnAttributes = context_attr & ~AcceptContextRetFlags.AllocatedMemory;
            Expiry = expiry.QuadPart;

            Token = AuthenticationToken.Parse(_creds.PackageName, _token_count++, false, token_buffer.ToArray());
            Done = !(result == SecStatusCode.SEC_I_CONTINUE_NEEDED || result == SecStatusCode.SEC_I_COMPLETE_AND_CONTINUE);
            return result;
        }


        private void Dispose(bool _)
        {
            if (_context != null)
            {
                SecurityNativeMethods.DeleteSecurityContext(_context);
            }
        }

        private string GetTargetName()
        {
            using (var buffer = new SafeStructureInOutBuffer<SecPkgContext_ClientSpecifiedTarget>())
            {
                var result = SecurityNativeMethods.QueryContextAttributesEx(_context, SECPKG_ATTR.CLIENT_SPECIFIED_TARGET, buffer, buffer.Length);
                if (result == SecStatusCode.SUCCESS)
                    return Marshal.PtrToStringUni(buffer.Result.sTargetName);
            }
            return string.Empty;
        }

        #endregion

        #region Public Properties
        /// <summary>
        /// The current authentication token.
        /// </summary>
        public AuthenticationToken Token { get; private set; }

        /// <summary>
        /// Whether the authentication is done.
        /// </summary>
        public bool Done { get; private set; }

        /// <summary>
        /// Current request attributes.
        /// </summary>
        public AcceptContextReqFlags RequestAttributes { get; set; }

        /// <summary>
        /// Current data representation.
        /// </summary>
        public SecDataRep DataRepresentation { get; set; }

        /// <summary>
        /// Current channel bindings.
        /// </summary>
        public byte[] ChannelBinding { get; set; }

        /// <summary>
        /// Current return attributes.
        /// </summary>
        public AcceptContextRetFlags ReturnAttributes { get; private set; }

        /// <summary>
        /// Current status flags.
        /// </summary>
        [Obsolete("Use ReturnAttributes")]
        public AcceptContextRetFlags Flags => ReturnAttributes;

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

        #endregion

        #region Public Methods
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
        /// Continue the authentication with the client token.
        /// </summary>
        /// <param name="token">The client token to continue authentication.</param>
        public void Continue(AuthenticationToken token)
        {
            Continue(token, new SecurityBuffer[0]);
        }

        /// <summary>
        /// Continue the authentication..
        /// </summary>
        /// <param name="token">The client token to continue authentication.</param>
        /// <param name="additional_input">Specify additional input buffers, does not need to include the token.</param>
        public void Continue(AuthenticationToken token, IEnumerable<SecurityBuffer> additional_input)
        {
            Continue(token, additional_input, new SecurityBuffer[0]);
        }

        /// <summary>
        /// Continue the authentication.
        /// </summary>
        /// <param name="token">The client token to continue authentication.</param>
        /// <param name="additional_input">Specify additional input buffers, does not need to include the token.</param>
        /// <param name="additional_output">Specify additional output buffers, does not need to include the token.</param>
        public void Continue(AuthenticationToken token, IEnumerable<SecurityBuffer> additional_input, IEnumerable<SecurityBuffer> additional_output)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            if (additional_input is null)
            {
                throw new ArgumentNullException(nameof(additional_input));
            }

            var input_buffers = new List<SecurityBuffer>
            {
                new SecurityBufferInOut(SecurityBufferType.Token, token.ToArray())
            };
            input_buffers.AddRange(additional_input);

            Continue(input_buffers, additional_output.ToList());
        }

        /// <summary>
        /// Continue the authentication.
        /// </summary>
        /// <param name="input_buffers">Additional input buffers for the continue. Does not contain a token.</param>
        /// <param name="additional_output">Specify additional output buffers, does not need to include the token.</param>
        /// <remarks>This sends the input buffers directly to the initialize call, it does not contain any token.</remarks>
        public void Continue(IEnumerable<SecurityBuffer> input_buffers, IEnumerable<SecurityBuffer> additional_output)
        {
            if (input_buffers is null)
            {
                throw new ArgumentNullException(nameof(input_buffers));
            }

            if (additional_output is null)
            {
                throw new ArgumentNullException(nameof(additional_output));
            }

            CallAccept(input_buffers.ToList(), additional_output.ToList(), true);
        }

        /// <summary>
        /// Continue the authentication. Will not pass any buffers to the accept call.
        /// </summary>
        public void Continue()
        {
            CallAccept(new List<SecurityBuffer>(), new List<SecurityBuffer>(), true);
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
        /// <param name="quality_of_protection">Quality of protection flags.</param>
        /// <returns>The encrypted message.</returns>
        /// <param name="sequence_no">The sequence number.</param>
        public EncryptedMessage EncryptMessage(byte[] message, SecurityQualityOfProtectionFlags quality_of_protection, int sequence_no)
        {
            return SecurityContextUtils.EncryptMessage(_context, quality_of_protection, message, sequence_no);
        }

        /// <summary>
        /// Encrypt a message for this context.
        /// </summary>
        /// <param name="messages">The messages to encrypt.</param>
        /// <param name="quality_of_protection">Quality of protection flags.</param>
        /// <returns>The signature for the messages.</returns>
        /// <remarks>The messages are encrypted in place. You can add buffers with the ReadOnly flag to prevent them being encrypted.</remarks>
        /// <param name="sequence_no">The sequence number.</param>
        public byte[] EncryptMessage(IEnumerable<SecurityBuffer> messages, SecurityQualityOfProtectionFlags quality_of_protection, int sequence_no)
        {
            return SecurityContextUtils.EncryptMessage(_context, quality_of_protection, messages, sequence_no);
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
        /// Export and delete the current security context.
        /// </summary>
        /// <returns>The exported security context.</returns>
        /// <remarks>The security context will not longer be usable afterwards.</remarks>
        public ExportedSecurityContext Export()
        {
            var context = SecurityContextUtils.ExportContext(_context, SecPkgContextExportFlags.DeleteOld, _creds.PackageName, false);
            Dispose();
            return context;
        }

        #endregion

        #region Constructors
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
            RequestAttributes = req_attributes & ~AcceptContextReqFlags.AllocateMemory;
            DataRepresentation = data_rep;
            _token_count = 0;
            ChannelBinding = channel_binding;
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
        #endregion

        #region IDisposable Implementation
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
        ~ServerAuthenticationContext()
        {
            Dispose(false);
        }
        #endregion
    }
}
