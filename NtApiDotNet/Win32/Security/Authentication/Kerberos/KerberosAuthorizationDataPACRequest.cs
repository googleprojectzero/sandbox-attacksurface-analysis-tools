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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Kerberos pre-authentication data to include a PAC.
    /// </summary>
    public sealed class KerberosPreAuthenticationDataPACRequest : KerberosPreAuthenticationData
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        public KerberosPreAuthenticationDataPACRequest(bool include_pac) 
            : base(KerberosPreAuthenticationType.PA_PAC_REQUEST)
        {
            IncludePac = include_pac;
        }

        private protected override byte[] GetData()
        {
            DERBuilder builder = new DERBuilder();
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, b => b.WriteBoolean(IncludePac));
            }
            return builder.ToArray();
        }

        /// <summary>
        /// Indicates whether to include the PAC.
        /// </summary>
        public bool IncludePac { get; }
    }
}
