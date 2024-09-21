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

using NtCoreLib.Utilities.Memory;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace NtCoreLib.Net.Firewall;

/// <summary>
/// Class to represent a certificate credential.
/// </summary>
public sealed class IkeCertificateCredential : IkeCredential
{
    /// <summary>
    /// Certificate subject name.
    /// </summary>
    public X500DistinguishedName SubjectName { get; }
    /// <summary>
    /// Certificatehash.
    /// </summary>
    public byte[] CertHash { get; }
    /// <summary>
    /// Flags.
    /// </summary>
    public IkeextCertCredentialFlags Flags;
    /// <summary>
    /// Certificate.
    /// </summary>
    public X509Certificate2 Certificate { get; }

    internal IkeCertificateCredential(IKEEXT_CREDENTIAL1 creds) : base(creds)
    {
        var cred = creds.cred.ReadStruct<IKEEXT_CERTIFICATE_CREDENTIAL1>();
        SubjectName = new X500DistinguishedName(cred.subjectName.ToArray());
        CertHash = cred.certHash.ToArray();
        Flags = cred.flags;
        try
        {
            Certificate = new X509Certificate2(cred.certificate.ToArray());
        }
        catch (CryptographicException)
        {
        }
    }

    /// <summary>
    /// Overridden ToString method.
    /// </summary>
    /// <returns>The pair as a string.</returns>
    public override string ToString()
    {
        return $"{AuthenticationMethodType} - {SubjectName.Format(false)}";
    }
}
