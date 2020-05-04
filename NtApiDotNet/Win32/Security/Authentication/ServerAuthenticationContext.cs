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

using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Class to represent a server authentication context.
    /// </summary>
    public sealed class ServerAuthenticationContext : IDisposable, IAuthenticationContext
    {
        private readonly CredentialHandle _creds;
        private readonly SecHandle _context;
        private readonly AcceptContextReqFlags _req_flags;
        private readonly SecDataRep _data_rep;
        private readonly byte[] _channel_binding;
        private bool _new_context;
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
        public byte[] SessionKey => GetSessionKey(_context);

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
            _context = new SecHandle();
            _req_flags = req_attributes & ~AcceptContextReqFlags.AllocateMemory;
            _data_rep = data_rep;
            _new_context = true;
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

        private bool GenServerContext(AuthenticationToken token)
        {
            bool new_context = _new_context;
            _new_context = false;
            using (DisposableList list = new DisposableList())
            {
                SecBuffer out_sec_buffer = list.AddResource(new SecBuffer(SecBufferType.Token, 64*1024));
                SecBufferDesc out_buffer_desc = list.AddResource(new SecBufferDesc(out_sec_buffer));

                List<SecBuffer> buffers = new List<SecBuffer>();
                buffers.Add(list.AddResource(new SecBuffer(SecBufferType.Token, token.ToArray())));
                if (_channel_binding != null)
                {
                    buffers.Add(list.AddResource(SecBuffer.CreateForChannelBinding(_channel_binding)));
                }
                SecBufferDesc in_buffer_desc = list.AddResource(new SecBufferDesc(buffers.ToArray()));

                LargeInteger expiry = new LargeInteger();
                SecStatusCode result = SecurityNativeMethods.AcceptSecurityContext(_creds.CredHandle, new_context ? null : _context,
                    in_buffer_desc, _req_flags, _data_rep, _context, out_buffer_desc, out AcceptContextRetFlags context_attr, expiry).CheckResult();
                Flags = context_attr;
                Expiry = expiry.QuadPart;
                if (result == SecStatusCode.CompleteNeeded || result == SecStatusCode.CompleteAndContinue)
                {
                    SecurityNativeMethods.CompleteAuthToken(_context, out_buffer_desc).CheckResult();
                }

                Token = AuthenticationToken.Parse(_creds.PackageName, _token_count++, false, out_buffer_desc.ToArray()[0].ToArray());
                return !(result == SecStatusCode.ContinueNeeded || result == SecStatusCode.CompleteAndContinue);
            }
        }

        void IDisposable.Dispose()
        {
            if (!_new_context)
                SecurityNativeMethods.DeleteSecurityContext(_context);
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

        internal static byte[] GetSessionKey(SecHandle context)
        {
            using (var buffer = new SafeStructureInOutBuffer<SecPkgContext_SessionKey>())
            {
                var result = SecurityNativeMethods.QueryContextAttributesEx(context, SECPKG_ATTR.SESSION_KEY, buffer, buffer.Length);
                if (result == SecStatusCode.Success)
                {
                    byte[] ret = new byte[buffer.Result.SessionKeyLength];
                    Marshal.Copy(buffer.Result.SessionKey, ret, 0, ret.Length);
                    return ret;
                }
            }
            return new byte[0];
        }
    }
}
