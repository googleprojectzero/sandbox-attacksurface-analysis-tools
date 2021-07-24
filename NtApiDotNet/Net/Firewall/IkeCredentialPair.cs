//  Copyright 2021 Google LLC. All Rights Reserved.
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

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Structure to represent a pair of credentials.
    /// </summary>
    public struct IkeCredentialPair
    {
        /// <summary>
        /// Local credentials.
        /// </summary>
        public IkeCredential Local { get; }

        /// <summary>
        /// Peer credentials.
        /// </summary>
        public IkeCredential Peer { get; }

        internal IkeCredentialPair(IKEEXT_CREDENTIAL_PAIR1 pair)
        {
            Local = IkeCredential.Create(pair.localCredentials);
            Peer = IkeCredential.Create(pair.peerCredentials);
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The pair as a string.</returns>
        public override string ToString()
        {
            return $"Local: {Local} - Peer: {Peer}";
        }
    }
}
