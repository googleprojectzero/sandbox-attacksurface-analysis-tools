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

using NtApiDotNet.Win32.Security.Authentication.Kerberos;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Credential.AuthIdentity
{
    /// <summary>
    /// Class to represent a keytab packed credentials structure.
    /// </summary>
    public sealed class SecWinNtAuthPackedCredentialKeyTab : SecWinNtAuthPackedCredential
    {
        /// <summary>
        /// The list of kerberos keys in the keytab.
        /// </summary>
        public IReadOnlyList<KerberosAuthenticationKey> Keys { get; }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">The list of keys for the keytab.</param>
        public SecWinNtAuthPackedCredentialKeyTab(IEnumerable<KerberosAuthenticationKey> keys)
            : this(KerberosUtils.GenerateKeyTabFile(keys), keys)
        {
        }

        internal SecWinNtAuthPackedCredentialKeyTab(byte[] keytab, IEnumerable<KerberosAuthenticationKey> keys)
            : base(SecWinNtPackedCredentialTypes.KeyTab, keytab)
        {
            if (keys is null)
            {
                throw new ArgumentNullException(nameof(keys));
            }

            Keys = keys.ToList().AsReadOnly();
        }
    }
}
