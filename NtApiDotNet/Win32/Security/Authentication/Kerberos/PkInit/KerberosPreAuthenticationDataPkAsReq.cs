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
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.PkInit
{
    /// <summary>
    /// Class to represent the PA-PK-AS-REQ pre-authentication data.
    /// </summary>
    public sealed class KerberosPreAuthenticationDataPkAsReq : KerberosPreAuthenticationData
    {
        /// <summary>
        /// The signed AuthPack data.
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

        /// <summary>
        /// Create a PA-PK-AS-REQ pre-authentication data from an auth pack.
        /// </summary>
        /// <param name="auth_pack">The auth pack for the PA-DATA.</param>
        /// <param name="certificate">The certificate used to signed the auth pack.</param>
        /// <returns>The created PA-PK-AS-REQ pre-authentication data.</returns>
        public static KerberosPreAuthenticationDataPkAsReq Create(KerberosPkInitAuthPack auth_pack, X509Certificate2 certificate)
        {
            if (auth_pack is null)
            {
                throw new ArgumentNullException(nameof(auth_pack));
            }

            ContentInfo contents = new ContentInfo(new Oid(OIDValues.PKINIT_AUTHDATA), auth_pack.ToArray());
            SignedCms signed_authpack = new SignedCms(contents);
            CmsSigner signer = new CmsSigner(certificate);
            signed_authpack.ComputeSignature(signer);
            return new KerberosPreAuthenticationDataPkAsReq(signed_authpack);
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

        internal static KerberosPreAuthenticationDataPkAsReq Parse(byte[] data)
        {
            try
            {
                DERValue[] values = DERParser.ParseData(data, 0);
                if (values.Length != 1 || !values[0].CheckSequence())
                    throw new InvalidDataException();

                SignedCms signed_auth_pack = null;
                foreach (var next in values[0].Children)
                {
                    if (next.Type != DERTagType.ContextSpecific)
                        throw new InvalidDataException();
                    switch (next.Tag)
                    {
                        case 0:
                            signed_auth_pack = KerberosPkInitUtils.ParseSignedData(next.Data);
                            break;
                        default:
                            throw new InvalidDataException();
                    }
                }
                return new KerberosPreAuthenticationDataPkAsReq(signed_auth_pack);
            }
            catch (CryptographicException ex)
            {
                throw new InvalidDataException("Invalid PK-AS-REQ.", ex);
            }
        }
    }
}
