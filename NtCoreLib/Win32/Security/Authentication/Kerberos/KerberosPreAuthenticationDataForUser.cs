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

using NtApiDotNet.Utilities.ASN1.Builder;
using System;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent a PA-FOR-USER structure.
    /// </summary>
    public sealed class KerberosPreAuthenticationDataForUser : KerberosPreAuthenticationData
    {
        /// <summary>
        /// The user's principal name.
        /// </summary>
        public KerberosPrincipalName UserName { get; }

        /// <summary>
        /// The user's realm.
        /// </summary>
        public string UserRealm { get; }

        /// <summary>
        /// The checksum for the data.
        /// </summary>
        public KerberosChecksum Checksum { get; }

        /// <summary>
        /// The authentication package.
        /// </summary>
        public string AuthPackage { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="username">The user's principal name.</param>
        /// <param name="userrealm">The user's realm.</param>
        /// <param name="checksum">The checksum for the data.</param>
        /// <param name="auth_package">The authentication package.</param>
        public KerberosPreAuthenticationDataForUser(KerberosPrincipalName username, string userrealm, 
            KerberosChecksum checksum, string auth_package) 
            : base(KerberosPreAuthenticationType.PA_FOR_USER)
        {
            UserName = username ?? throw new ArgumentNullException(nameof(username));
            UserRealm = userrealm ?? throw new ArgumentNullException(nameof(userrealm));
            Checksum = checksum ?? throw new ArgumentNullException(nameof(checksum));
            AuthPackage = auth_package ?? throw new ArgumentNullException(nameof(auth_package)); ;
        }

        private protected override byte[] GetData()
        {
            DERBuilder builder = new DERBuilder();
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, UserName);
                seq.WriteContextSpecific(1, UserRealm);
                seq.WriteContextSpecific(2, Checksum);
                seq.WriteContextSpecific(3, AuthPackage);
            }
            return builder.ToArray();
        }
    }
}
