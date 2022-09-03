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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.PkInit
{
    /// <summary>
    /// AuthPack value for PKINIT.
    /// </summary>
    public sealed class KerberosPkInitAuthPack : IDERObject
    {
        /// <summary>
        /// The PkAuthenticator.
        /// </summary>
        public KerberosPkInitPkAuthenticator PkAuthenticator { get; }

        // TODO: The other properties when this supports DH/ECDH.

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="pk_authenticator">The PkAuthenticator.</param>
        public KerberosPkInitAuthPack(KerberosPkInitPkAuthenticator pk_authenticator)
        {
            PkAuthenticator = pk_authenticator;
        }

        /// <summary>
        /// Convert the AuthPack to an array.
        /// </summary>
        /// <returns>The AuthPack as an array.</returns>
        public byte[] ToArray()
        {
            DERBuilder builder = new DERBuilder();
            builder.WriteObject(this);
            return builder.ToArray();
        }

        /*
         AuthPack ::= SEQUENCE {
          pkAuthenticator         [0] PKAuthenticator,
          clientPublicValue       [1] SubjectPublicKeyInfo OPTIONAL,
                   -- Type SubjectPublicKeyInfo is defined in
                   -- [RFC3280].
                   -- Specifies Diffie-Hellman domain parameters
                   -- and the client's public key value [IEEE1363].
                   -- The DH public key value is encoded as a BIT
                   -- STRING according to [RFC3279].
                   -- This field is present only if the client wishes
                   -- to use the Diffie-Hellman key agreement method.
          supportedCMSTypes       [2] SEQUENCE OF AlgorithmIdentifier
                                      OPTIONAL,
                   -- Type AlgorithmIdentifier is defined in
                   -- [RFC3280].
                   -- List of CMS algorithm [RFC3370] identifiers
                   -- that identify key transport algorithms, or
                   -- content encryption algorithms, or signature
                   -- algorithms supported by the client in order of
                   -- (decreasing) preference.
          clientDHNonce           [3] DHNonce OPTIONAL,
                   -- Present only if the client indicates that it
                   -- wishes to reuse DH keys or to allow the KDC to
                   -- do so (see Section 3.2.3.1).
          ...
       }
        */
        void IDERObject.Write(DERBuilder builder)
        {
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, PkAuthenticator);
            }
        }
    }
}
