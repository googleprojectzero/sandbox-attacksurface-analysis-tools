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

using NtApiDotNet.Utilities.ASN1;
using NtApiDotNet.Utilities.ASN1.Builder;
using System;
using System.IO;
using System.Security.Cryptography.Pkcs;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.PkInit
{
    /// <summary>
    /// Class to represent the PA-PK-AS-REP pre-authentication data.
    /// </summary>
    public sealed class KerberosPreAuthenticationDataPkAsRep : KerberosPreAuthenticationData
    {
        /// <summary>
        /// The encrypted key pack.
        /// </summary>
        public EnvelopedCms EncryptedKeyPack { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="encrypted_key_pack">The signed auth pack.</param>
        public KerberosPreAuthenticationDataPkAsRep(EnvelopedCms encrypted_key_pack)
            : base(KerberosPreAuthenticationType.PA_PK_AS_REQ)
        {
            EncryptedKeyPack = encrypted_key_pack ?? throw new ArgumentNullException(nameof(encrypted_key_pack));
        }

        internal static KerberosPreAuthenticationDataPkAsRep Parse(byte[] data)
        {
            DERValue[] values = DERParser.ParseData(data, 0);
            if (values.Length != 1 || values[0].Type != DERTagType.ContextSpecific)
                throw new InvalidDataException();

            switch (values[0].Tag)
            {
                case 1:
                    EnvelopedCms encrypted_key_pack = new EnvelopedCms();
                    encrypted_key_pack.Decode(values[0].Data);
                    return new KerberosPreAuthenticationDataPkAsRep(encrypted_key_pack);
                default:
                    throw new InvalidDataException();
            }
        }

        private protected override byte[] GetData()
        {
            DERBuilder builder = new DERBuilder();
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(1, false, EncryptedKeyPack.Encode());
            }
            return builder.ToArray();
        }
    }
}
