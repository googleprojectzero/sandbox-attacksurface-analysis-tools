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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Utilities
{
    /// <summary>
    /// Class to represent a cache file principal.
    /// </summary>
    public sealed class KerberosCredentialCacheFilePrincipal
    {
        /// <summary>
        /// The kerberos principal name.
        /// </summary>
        public KerberosPrincipalName Name { get; }
        /// <summary>
        /// The kerberos realm.
        /// </summary>
        public string Realm { get; }

        internal bool IsConfigEntry => Realm.Equals("X-CACHECONF:") && Name.Names.Count > 1 && Name.Names[0] == "krb5_ccache_conf_data";

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="name">The kerberos principal name.</param>
        /// <param name="realm">The kerberos realm.</param>
        public KerberosCredentialCacheFilePrincipal(KerberosPrincipalName name, string realm)
        {
            if (name is null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            if (realm is null)
            {
                throw new ArgumentNullException(nameof(realm));
            }

            Name = name;
            Realm = realm;
        }
    }
}
