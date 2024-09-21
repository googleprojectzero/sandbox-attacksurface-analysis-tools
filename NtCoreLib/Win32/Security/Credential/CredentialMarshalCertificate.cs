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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Win32.Security.Interop;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace NtCoreLib.Win32.Security.Credential;

/// <summary>
/// Unmarshalled certificate credentials.
/// </summary>
public sealed class CredentialMarshalCertificate : CredentialMarshalBase
{
    private const int CERT_HASH_LENGTH = 20;

    /// <summary>
    /// The hash of the certificate.
    /// </summary>
    public byte[] HashOfCert { get; }

    internal override SafeBuffer ToBuffer()
    {
        CERT_CREDENTIAL_INFO cred = new();
        cred.cbSize = Marshal.SizeOf(cred);
        cred.rgbHashOfCert = HashOfCert.CloneBytes();
        Array.Resize(ref cred.rgbHashOfCert, CERT_HASH_LENGTH);
        return cred.ToBuffer();
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    public CredentialMarshalCertificate(X509Certificate certificate) 
        : this(certificate?.GetCertHash() ?? throw new ArgumentNullException(nameof(certificate)))
    {
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="hash_of_cert">The hash of the certificate (should be 20 bytes)</param>
    public CredentialMarshalCertificate(byte[] hash_of_cert) : base(CredMarshalType.CertCredential)
    {
        if (hash_of_cert is null)
            throw new ArgumentNullException(nameof(hash_of_cert));
        if (hash_of_cert.Length != CERT_HASH_LENGTH)
            throw new ArgumentException($"Hash length must be {CERT_HASH_LENGTH} bytes.", nameof(hash_of_cert));
        HashOfCert = hash_of_cert.CloneBytes();
    }

    internal CredentialMarshalCertificate(CERT_CREDENTIAL_INFO info) : base(CredMarshalType.CertCredential)
    {
        HashOfCert = info.rgbHashOfCert;
    }
}
