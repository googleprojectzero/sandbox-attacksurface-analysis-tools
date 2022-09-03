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
using System.Security.Cryptography.Pkcs;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.PkInit
{
    /// <summary>
    /// Class to represent the PA-PK-AS-REQ pre-authentication data.
    /// </summary>
    public sealed class KerberosPreAuthenticationDataPkAsReq : KerberosPreAuthenticationData
    {
        /// <summary>
        /// The signed AuthPack data data.
        /// </summary>
        public SignedCms SignedAuthPack { get; }

        // TODO: Other properties.

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="signed_auth_pack">The signed auth pack.</param>
        public KerberosPreAuthenticationDataPkAsReq(SignedCms signed_auth_pack) 
            : base(KerberosPreAuthenticationType.PA_PK_AS_REQ)
        {
            SignedAuthPack = signed_auth_pack ?? throw new ArgumentNullException(nameof(signed_auth_pack));
        }

        private protected override byte[] GetData()
        {
            DERBuilder builder = new DERBuilder();
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, false, SignedAuthPack.Encode());
            }
            return builder.ToArray();
        }
    }
}
