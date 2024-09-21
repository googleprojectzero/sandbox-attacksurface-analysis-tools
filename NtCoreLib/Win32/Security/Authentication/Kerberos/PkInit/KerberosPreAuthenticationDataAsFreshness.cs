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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.PkInit
{
    /// <summary>
    /// Class to represent PKINIT AS Freshness data.
    /// </summary>
    public sealed class KerberosPreAuthenticationDataAsFreshness : KerberosPreAuthenticationData
    {
        /// <summary>
        /// The freshness token.
        /// </summary>
        public byte[] FreshnessToken { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="freshness_token">The data for the preauthentication.</param>
        public KerberosPreAuthenticationDataAsFreshness(byte[] freshness_token) 
            : base(KerberosPreAuthenticationType.PA_AS_FRESHNESS)
        {
            if (freshness_token is null)
            {
                throw new ArgumentNullException(nameof(freshness_token));
            }

            FreshnessToken = freshness_token.CloneBytes();
        }

        private protected override byte[] GetData()
        {
            return FreshnessToken;
        }
    }
}
