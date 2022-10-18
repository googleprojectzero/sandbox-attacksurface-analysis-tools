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
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent PA-ENC-TIMESTAMP pre-authentication data.
    /// </summary>
    public sealed class KerberosPreAuthenticationDataEncTimestamp : KerberosPreAuthenticationData
    {
        /// <summary>
        /// The encrypted timestamp data.
        /// </summary>
        public KerberosEncryptedData EncryptedData { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="encrypted_data">The encrypted timestamp data.</param>
        public KerberosPreAuthenticationDataEncTimestamp(KerberosEncryptedData encrypted_data)
            : base(KerberosPreAuthenticationType.PA_ENC_TIMESTAMP)
        {
            EncryptedData = encrypted_data ?? throw new ArgumentNullException(nameof(encrypted_data));
        }

        /// <summary>
        /// Create an encrypted timestamp.
        /// </summary>
        /// <param name="timestamp">The current timestamp.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="usecs">Optional usecs for the timestamp.</param>
        /// <param name="key_version">Optional key version for the encrypted data.</param>
        /// <returns>The encrypted timestamp.</returns>
        public static KerberosPreAuthenticationDataEncTimestamp Create(KerberosTime timestamp, KerberosAuthenticationKey key, int? usecs = null, int? key_version = null)
        {
            if (timestamp is null)
            {
                throw new ArgumentNullException(nameof(timestamp));
            }

            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            DERBuilder builder = new DERBuilder();
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, timestamp);
                seq.WriteContextSpecific(1, usecs);
            }

            var enc_data = KerberosEncryptedData.Create(KerberosEncryptionType.NULL, builder.ToArray());
            return new KerberosPreAuthenticationDataEncTimestamp(enc_data.Encrypt(key, KerberosKeyUsage.AsReqPaEncTimestamp, key_version));
        }

        internal static KerberosPreAuthenticationDataEncTimestamp Parse(byte[] data)
        {
            return new KerberosPreAuthenticationDataEncTimestamp(KerberosEncryptedData.Parse(data));
        }

        private protected override byte[] GetData()
        {
            DERBuilder builder = new DERBuilder();
            builder.WriteObject(EncryptedData);
            return builder.ToArray();
        }

        private protected override void Format(StringBuilder builder)
        {
            builder.AppendLine(EncryptedData.Format());
        }
    }
}
