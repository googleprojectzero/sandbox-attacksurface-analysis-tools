//  Copyright 2021 Google Inc. All Rights Reserved.
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
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace NtApiDotNet.Win32.Security.Authentication.Schannel
{
    /// <summary>
    /// Credentials for the Schannel package.
    /// </summary>
    public sealed class SchannelCredentials : AuthenticationCredentials, IDisposable
    {
        private readonly List<X509Certificate2> _certs = new List<X509Certificate2>();
        private readonly List<SchannelAlgorithmType> _alg_types = new List<SchannelAlgorithmType>();

        /// <summary>
        /// Lifespan of a session in milliseconds.
        /// </summary>
        public int SessionLifespan { get; set; }

        /// <summary>
        /// Specify flags for credentials.
        /// </summary>
        public SchannelCredentialsFlags Flags { get; set; }

        /// <summary>
        /// Specify the supported protocols.
        /// </summary>
        public SchannelProtocolType Protocols { get; set; }

        /// <summary>
        /// Set the minimum cipher strength.
        /// </summary>
        public int MinimumCipherStrength { get; set; }

        /// <summary>
        /// Set the maximum cipher strength.
        /// </summary>
        public int MaximumCipherStrength { get; set; }

        /// <summary>
        /// Add a certificate the the credentials. This should contain a private key.
        /// </summary>
        /// <param name="certificate">The certificate to add.</param>
        public void AddCertificate(X509Certificate certificate)
        {
            X509Certificate2 cert2 = new X509Certificate2(certificate);
            if (!cert2.HasPrivateKey)
                throw new ArgumentException("Must provide a certificate with a private key.", nameof(certificate));
            _certs.Add(new X509Certificate2(certificate));
        }

        /// <summary>
        /// Add an algorithm type to the credentials.
        /// </summary>
        /// <param name="algorithm">The algorithm type.</param>
        public void AddAlgorithm(SchannelAlgorithmType algorithm)
        {
            _alg_types.Add(algorithm);
        }

        /// <summary>
        /// Dispose the credentials.
        /// </summary>
        public void Dispose()
        {
            foreach (var cert in _certs)
            {
                // X509Certificate only supports IDisposable from 4.6. Try manually.
                if (cert is IDisposable dispose)
                {
                    dispose.Dispose();
                }
            }
        }

        internal override SafeBuffer ToBuffer(DisposableList list, string package)
        {
            if (!AuthenticationPackage.CheckSChannel(package) 
                && !AuthenticationPackage.CheckCredSSP(package)
                && !AuthenticationPackage.CheckTSSSP(package))
            {
                throw new ArgumentException("Can only use SchannelCredentials for the Schannel or CredSSP package.", nameof(package));
            }
            SCHANNEL_CRED creds = new SCHANNEL_CRED
            {
                dwVersion = SCHANNEL_CRED.SCHANNEL_CRED_VERSION,
                dwSessionLifespan = SessionLifespan,
                dwFlags = Flags,
                grbitEnabledProtocols = Protocols,
                dwMinimumCipherStrength = MinimumCipherStrength,
                dwMaximumCipherStrength = MaximumCipherStrength
            };
            if (_certs.Count > 0)
            {
                IntPtr[] cred_handles = _certs.Select(c => c.Handle).ToArray();
                var array_buffer = list.AddResource(cred_handles.ToBuffer());
                creds.cCreds = cred_handles.Length;
                creds.paCred = array_buffer.DangerousGetHandle();
            }
            if (_alg_types.Count > 0)
            {
                creds.cSupportedAlgs = _alg_types.Count;
                creds.palgSupportedAlgs = list.AddResource(_alg_types.Select(a => (int)a).ToArray().ToBuffer()).DangerousGetHandle();
            }

            return creds.ToBuffer();
        }
    }
}
