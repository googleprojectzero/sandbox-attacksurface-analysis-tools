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

using NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder;
using System;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent a KERB_LOCAL authorization data value.
    /// </summary>
    public sealed class KerberosAuthorizationDataKerbLocal : KerberosAuthorizationData
    {
        /// <summary>
        /// The security context identifier for the KERB_LOCAL value.
        /// </summary>
        public byte[] SecurityContext { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="security_context">The security context identifier.</param>
        public KerberosAuthorizationDataKerbLocal(byte[] security_context)
            : base(KerberosAuthorizationDataType.KERB_LOCAL)
        {
            if (security_context is null)
            {
                throw new ArgumentNullException(nameof(security_context));
            }

            SecurityContext = security_context.CloneBytes();
        }

        private protected override void FormatData(StringBuilder builder)
        {
            builder.AppendLine($"Security Context: {NtObjectUtils.ToHexString(SecurityContext)}");
        }

        private protected override byte[] GetData()
        {
            return SecurityContext;
        }

        internal static bool Parse(byte[] data, out KerberosAuthorizationDataKerbLocal entry)
        {
            entry = new KerberosAuthorizationDataKerbLocal(data);
            return true;
        }

        /// <summary>
        /// Convert the authorization data into a builder.
        /// </summary>
        /// <returns>The authorization builder.</returns>
        public override KerberosAuthorizationDataBuilder ToBuilder()
        {
            return new KerberosAuthorizationDataKerbLocalBuilder()
            {
                SecurityContext = SecurityContext.CloneBytes()
            };
        }
    }
}
