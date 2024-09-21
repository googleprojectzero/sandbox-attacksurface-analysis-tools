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
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.PkInit
{
    /// <summary>
    /// Class to represent a ExternalPrincipalIdentifier structure.
    /// </summary>
    public sealed class KerberosPkInitExternalPrincipalIdentifier : IDERObject
    {
        /*
         ExternalPrincipalIdentifier ::= SEQUENCE {
          subjectName            [0] IMPLICIT OCTET STRING OPTIONAL,
                   -- Contains a PKIX type Name encoded according to
                   -- [RFC3280].
                   -- Identifies the certificate subject by the
                   -- distinguished subject name.
                   -- REQUIRED when there is a distinguished subject
                   -- name present in the certificate.
         issuerAndSerialNumber   [1] IMPLICIT OCTET STRING OPTIONAL,
                   -- Contains a CMS type IssuerAndSerialNumber encoded
                   -- according to [RFC3852].
                   -- Identifies a certificate of the subject.
                   -- REQUIRED for TD-INVALID-CERTIFICATES and
                   -- TD-TRUSTED-CERTIFIERS.
         subjectKeyIdentifier    [2] IMPLICIT OCTET STRING OPTIONAL,
                   -- Identifies the subject's public key by a key
                   -- identifier.  When an X.509 certificate is
                   -- referenced, this key identifier matches the X.509
                   -- subjectKeyIdentifier extension value.  When other
                   -- certificate formats are referenced, the documents
                   -- that specify the certificate format and their use
                   -- with the CMS must include details on matching the
                   -- key identifier to the appropriate certificate
                   -- field.
                   -- RECOMMENDED for TD-TRUSTED-CERTIFIERS.
          ...
       }
         */

        /// <summary>
        /// The subject name of the principal.
        /// </summary>
        public X500DistinguishedName SubjectName { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="subject_name">The subject name of the principal.</param>
        public KerberosPkInitExternalPrincipalIdentifier(X500DistinguishedName subject_name)
        {
            SubjectName = subject_name;
        }

        // TODO: Add remaining values.

        internal static KerberosPkInitExternalPrincipalIdentifier Parse(DERValue value)
        {
            if (!value.CheckSequence())
                throw new InvalidDataException();

            X500DistinguishedName subject_name = null;
            foreach (var next in value.Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    throw new InvalidDataException();
                switch (next.Tag)
                {
                    case 0:
                        subject_name = new X500DistinguishedName(next.Data);
                        break;
                    default:
                        throw new InvalidDataException();
                }
            }
            return new KerberosPkInitExternalPrincipalIdentifier(subject_name);
        }

        void IDERObject.Write(DERBuilder builder)
        {
            using (var seq = builder.CreateSequence())
            {
                if (SubjectName != null)
                {
                    seq.WriteContextSpecific(0, false, SubjectName.RawData);
                }
            }
        }
    }
}
