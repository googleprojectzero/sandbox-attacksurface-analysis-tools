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

using System;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Class to represent a client authentication context.
    /// </summary>
    public sealed class ClientAuthenticationContext : IDisposable
    {
        private readonly CredentialHandle _creds;
        private readonly InitializeContextReqFlags _req_attributes;
        private readonly SecHandle _context;
        private readonly string _target;
        private readonly SecDataRep _data_rep;

        /// <summary>
        /// The current authentication token.
        /// </summary>
        public byte[] Token { get; private set; }

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
        /// Constructor.
        /// </summary>
        /// <param name="creds">Credential handle.</param>
        /// <param name="req_attributes">Request attribute flags.</param>
        /// <param name="target">Target SPN (optional).</param>
        /// <param name="data_rep">Data representation.</param>
        public ClientAuthenticationContext(CredentialHandle creds, InitializeContextReqFlags req_attributes,
            string target, SecDataRep data_rep)
        {
            _creds = creds;
            _req_attributes = req_attributes & ~InitializeContextReqFlags.AllocateMemory;
            _context = new SecHandle();
            _target = target;
            _data_rep = data_rep;
            Continue(null);
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="creds">Credential handle.</param>
        /// <param name="req_attributes">Request attribute flags.</param>
        /// <param name="data_rep">Data representation.</param>
        public ClientAuthenticationContext(CredentialHandle creds, InitializeContextReqFlags req_attributes, SecDataRep data_rep)
            : this(creds, req_attributes, null, data_rep)
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
        public void Continue(byte[] token)
        {
            Done = GenClientContext(token);
        }

        private bool GenClientContext(byte[] token)
        {
            using (DisposableList list = new DisposableList())
            {
                SecStatusCode result = 0;

                SecBuffer out_sec_buffer = list.AddResource(new SecBuffer(SecBufferType.Token, 8192));
                SecBufferDesc out_buffer_desc = list.AddResource(new SecBufferDesc(out_sec_buffer));

                InitializeContextRetFlags flags;
                LargeInteger expiry = new LargeInteger();
                if (token != null)
                {
                    SecBuffer in_sec_buffer = list.AddResource(new SecBuffer(SecBufferType.Token, token));
                    SecBufferDesc in_buffer_desc = list.AddResource(new SecBufferDesc(in_sec_buffer));
                    result = SecurityNativeMethods.InitializeSecurityContext(_creds.CredHandle, _context, _target, _req_attributes, 0,
                        _data_rep, in_buffer_desc, 0, _context, out_buffer_desc, out flags, expiry).CheckResult();
                    Flags = flags;
                }
                else
                {
                    result = SecurityNativeMethods.InitializeSecurityContext(_creds.CredHandle, null, _target,
                        _req_attributes, 0, _data_rep, null, 0, _context,
                        out_buffer_desc, out flags, expiry).CheckResult();
                }

                Expiry = expiry.QuadPart;
                Flags = flags;
                if (result == SecStatusCode.CompleteNeeded || result == SecStatusCode.CompleteAndContinue)
                {
                    SecurityNativeMethods.CompleteAuthToken(_context, out_buffer_desc).CheckResult();
                }

                Token = out_buffer_desc.ToArray()[0].ToArray();
                return !(result == SecStatusCode.ContinueNeeded || result == SecStatusCode.CompleteAndContinue);
            }
        }

        void IDisposable.Dispose()
        {
            SecurityNativeMethods.DeleteSecurityContext(_context);
        }
    }
}
