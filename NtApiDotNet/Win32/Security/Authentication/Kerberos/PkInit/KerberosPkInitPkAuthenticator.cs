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
    /// PkAuthenticator value for PKINIT.
    /// </summary>
    public sealed class KerberosPkInitPkAuthenticator : IDERObject
    {
        /// <summary>
        /// Client time usecs.
        /// </summary>
        public int ClientUSec { get; }
        /// <summary>
        /// Client time.
        /// </summary>
        public KerberosTime ClientTime { get; }
        /// <summary>
        /// Request nonce.
        /// </summary>
        public int Nonce { get; }
        /// <summary>
        /// SHA1 checksum of KDC-REQ-BODY.
        /// </summary>
        public byte[] PaChecksum { get; }
        /// <summary>
        /// The optional freshness token for RFC8070.
        /// </summary>
        public byte[] FreshnessToken { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="client_usec">Client time usecs.</param>
        /// <param name="client_time">Client time.</param>
        /// <param name="nonce">Request nonce.</param>
        /// <param name="pa_checksum">SHA1 checksum of KDC-REQ-BODY.</param>
        /// <param name="freshness_token">Freshness token.</param>
        public KerberosPkInitPkAuthenticator(int client_usec, 
            KerberosTime client_time, int nonce, byte[] pa_checksum, 
            byte[] freshness_token)
        {
            ClientUSec = client_usec;
            ClientTime = client_time ?? throw new System.ArgumentNullException(nameof(client_time));
            Nonce = nonce;
            PaChecksum = pa_checksum;
            FreshnessToken = freshness_token;
        }

        /*
        PKAuthenticator ::= SEQUENCE {
          cusec                   [0] INTEGER (0..999999),
          ctime                   [1] KerberosTime,
                   -- cusec and ctime are used as in [RFC4120], for
                   -- replay prevention.
          nonce                   [2] INTEGER (0..4294967295),
                   -- Chosen randomly;  this nonce does not need to
                   -- match with the nonce in the KDC-REQ-BODY.
          paChecksum              [3] OCTET STRING OPTIONAL,
                   -- MUST be present.
                   -- Contains the SHA1 checksum, performed over
                   -- KDC-REQ-BODY.
          ...,
          freshnessToken     [4] OCTET STRING OPTIONAL,
            -- PA_AS_FRESHNESS padata value as received from the
            -- KDC. MUST be present if sent by KDC
      ...
       }
       */
        void IDERObject.Write(DERBuilder builder)
        {
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, ClientUSec);
                seq.WriteContextSpecific(1, ClientTime);
                seq.WriteContextSpecific(2, Nonce);
                seq.WriteContextSpecific(3, PaChecksum);
                seq.WriteContextSpecific(4, FreshnessToken);
            }
        }
    }
}
