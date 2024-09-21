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
    /// Class to represent the DHRepInfo structure for PA-PK-AS-REP pre-authentication data.
    /// </summary>
    public sealed class KerberosPkAsRepDHRepInfo : IDERObject
    {
        /// <summary>
        /// The signed DH data.
        /// </summary>
        public SignedCms DHSignedData { get; }

        /// <summary>
        /// The optional server DH nonce.
        /// </summary>
        public byte[] ServerDHNonce { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="dh_signed_data">The signed DH data.</param>
        /// <param name="server_dh_nonce">The optional server DH nonce.</param>
        public KerberosPkAsRepDHRepInfo(SignedCms dh_signed_data, byte[] server_dh_nonce)
        {
            DHSignedData = dh_signed_data ?? throw new ArgumentNullException(nameof(dh_signed_data));
            ServerDHNonce = server_dh_nonce;
        }

        internal static KerberosPkAsRepDHRepInfo Parse(DERValue[] values)
        {
            if (values.Length != 1 || !values[0].CheckSequence())
                throw new InvalidDataException();

            SignedCms signed = null;
            byte[] server_nonce = null;

            foreach (var next in values[0].Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    throw new InvalidDataException();
                switch (next.Tag)
                {
                    case 0:
                        signed = KerberosPkInitUtils.ParseSignedData(next.Data);
                        break;
                    case 1:
                        server_nonce = next.ReadChildOctetString();
                        break;
                    default:
                        throw new InvalidDataException();
                }
            }
            return new KerberosPkAsRepDHRepInfo(signed, server_nonce);
        }

        void IDERObject.Write(DERBuilder builder)
        {
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, false, DHSignedData.Encode());
                seq.WriteContextSpecific(1, ServerDHNonce);
            }
        }
    }
}
