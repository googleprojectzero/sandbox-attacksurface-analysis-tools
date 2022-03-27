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

using System;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Server
{
    /// <summary>
    /// Base class for a KDC server.
    /// </summary>
    public abstract class KerberosKDCServer : IDisposable
    {
        private readonly IKerberosKDCServerListener _listener;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="listener">The network listener.</param>
        protected KerberosKDCServer(IKerberosKDCServerListener listener)
        {
            _listener = listener ?? throw new ArgumentNullException(nameof(listener));
        }

        /// <summary>
        /// Handle a request.
        /// </summary>
        /// <param name="request">The request to handle.</param>
        /// <returns>The reply.</returns>
        protected abstract byte[] HandleRequest(byte[] request);

        /// <summary>
        /// Dispose the server.
        /// </summary>
        public virtual void Dispose()
        {
            _listener.Dispose();
        }

        /// <summary>
        /// Start the server.
        /// </summary>
        public void Start()
        {
            _listener.Start(HandleRequest);
        }

        /// <summary>
        /// Stop the server.
        /// </summary>
        public void Stop()
        {
            _listener.Stop();
        }
    }
}
