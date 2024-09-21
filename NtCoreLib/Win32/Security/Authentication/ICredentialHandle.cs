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

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Interface for a credential handle.
    /// </summary>
    public interface ICredentialHandle : IDisposable
    {
        /// <summary>
        /// Name of the authentication package used.
        /// </summary>
        string PackageName { get; }

        /// <summary>
        /// Create a client authentication context.
        /// </summary>
        /// <param name="req_attributes">Request attribute flags.</param>
        /// <param name="target">Target SPN (optional).</param>
        /// <param name="data_rep">Data representation.</param>
        /// <param name="channel_binding">Optional channel binding token.</param>
        /// <param name="initialize">Specify to default initialize the context. Must call Continue with an auth token to initialize.</param>
        /// <param name="owns_credentials">Specify to make the new context own the credential handle so that it doesn't need to be disposed of.</param>
        /// <returns>The client authentication context.</returns>
        IClientAuthenticationContext CreateClient(InitializeContextReqFlags req_attributes = InitializeContextReqFlags.None,
            string target = null, SecurityChannelBinding channel_binding = null, SecDataRep data_rep = SecDataRep.Native, 
            bool initialize = true, bool owns_credentials = false);

        /// <summary>
        /// Create a server authentication context.
        /// </summary>
        /// <param name="req_attributes">Request attribute flags.</param>
        /// <param name="channel_binding">Optional channel binding token.</param>
        /// <param name="data_rep">Data representation.</param>
        /// <param name="owns_credentials">Specify to make the new context own the credential handle so that it doesn't need to be disposed of.</param>
        /// <returns>The server authentication context.</returns>
        IServerAuthenticationContext CreateServer(AcceptContextReqFlags req_attributes = AcceptContextReqFlags.None,
            SecurityChannelBinding channel_binding = null, SecDataRep data_rep = SecDataRep.Native, bool owns_credentials = false);
    }
}
