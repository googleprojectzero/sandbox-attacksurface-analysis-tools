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

using NtApiDotNet.Win32.SafeHandles;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Credential
{
    /// <summary>
    /// Abstract unmarshalled credentials base.
    /// </summary>
    public abstract class CredentialMarshalBase
    {
        /// <summary>
        /// The type of credentials.
        /// </summary>
        public CredMarshalType CredType { get; }

        internal abstract SafeBuffer ToBuffer();

        internal static CredentialMarshalBase GetCredentialBuffer(SafeCredBuffer buffer, CredMarshalType cred_type)
        {
            using (buffer)
            {
                switch (cred_type)
                {
                    case CredMarshalType.CertCredential:
                        return new CredentialMarshalCertificate(buffer.ReadStructUnsafe<CERT_CREDENTIAL_INFO>());
                    case CredMarshalType.UsernameTargetCredential:
                        return new CredentialMarshalUsernameTarget(buffer.ReadStructUnsafe<USERNAME_TARGET_CREDENTIAL_INFO>());
                    case CredMarshalType.BinaryBlobCredential:
                        return new CredentialMarshalBinaryBlob(buffer.ReadStructUnsafe<BINARY_BLOB_CREDENTIAL_INFO>());
                    default:
                        return new CredentialMarshalUnknown(buffer.Detach(), cred_type);
                }
            }
        }

        private protected CredentialMarshalBase(CredMarshalType cred_type)
        {
            CredType = cred_type;
        }
    }

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
            CERT_CREDENTIAL_INFO cred = new CERT_CREDENTIAL_INFO();
            cred.cbSize = Marshal.SizeOf(cred);
            cred.rgbHashOfCert = (byte[])HashOfCert.Clone();
            Array.Resize(ref cred.rgbHashOfCert, CERT_HASH_LENGTH);
            return cred.ToBuffer();
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
            HashOfCert = (byte[])hash_of_cert.Clone();
        }

        internal CredentialMarshalCertificate(CERT_CREDENTIAL_INFO info) : base(CredMarshalType.CertCredential)
        {
            HashOfCert = info.rgbHashOfCert;
        }
    }

    /// <summary>
    /// Unmarshalled certificate credentials.
    /// </summary>
    public sealed class CredentialMarshalUsernameTarget : CredentialMarshalBase
    {
        /// <summary>
        /// The username target.
        /// </summary>
        public string UserName { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="username">The username target.</param>
        public CredentialMarshalUsernameTarget(string username) : base(CredMarshalType.UsernameTargetCredential)
        {
            if (username is null)
                throw new ArgumentNullException(nameof(username));
            UserName = username;
        }

        internal override SafeBuffer ToBuffer()
        {
            return new USERNAME_TARGET_CREDENTIAL_INFO() { UserName = UserName }.ToBuffer();
        }

        internal CredentialMarshalUsernameTarget(USERNAME_TARGET_CREDENTIAL_INFO info) : base(CredMarshalType.UsernameTargetCredential)
        {
            UserName = info.UserName;
        }
    }

    /// <summary>
    /// Unmarshalled binary blob credentials.
    /// </summary>
    public sealed class CredentialMarshalBinaryBlob : CredentialMarshalBase
    {
        /// <summary>
        /// The binary blob.
        /// </summary>
        public byte[] Blob { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="blob">The binary blob credentials.</param>
        public CredentialMarshalBinaryBlob(byte[] blob) : base(CredMarshalType.BinaryBlobCredential)
        {
            if (blob is null)
                throw new ArgumentNullException(nameof(blob));
            Blob = (byte[])blob.Clone();
        }

        internal override SafeBuffer ToBuffer()
        {
            using (var buffer = new SafeStructureInOutBuffer<BINARY_BLOB_CREDENTIAL_INFO>(Blob.Length, true))
            {
                var data = buffer.Data;
                data.WriteBytes(Blob);
                buffer.Result = new BINARY_BLOB_CREDENTIAL_INFO
                {
                    cbBlob = Blob.Length,
                    pbBlob = data.DangerousGetHandle()
                };
                return buffer.Detach();
            }
        }

        internal CredentialMarshalBinaryBlob(BINARY_BLOB_CREDENTIAL_INFO info) : base(CredMarshalType.BinaryBlobCredential)
        {
            Blob = new byte[info.cbBlob];
            Marshal.Copy(info.pbBlob, Blob, 0, info.cbBlob);
        }
    }

    /// <summary>
    /// Unmarshalled credentials unknown buffer..
    /// </summary>
    public sealed class CredentialMarshalUnknown : CredentialMarshalBase, IDisposable
    {
        /// <summary>
        /// The buffer for the credentials.
        /// </summary>
        public SafeBuffer Credential { get; }

        /// <summary>
        /// Dispose of the unmarshalled credentials.
        /// </summary>
        public void Dispose()
        {
            ((IDisposable)Credential).Dispose();
        }

        internal override SafeBuffer ToBuffer()
        {
            if (Credential.IsClosed)
                throw new ObjectDisposedException("Credential");
            return new SafeHGlobalBuffer(Credential.DangerousGetHandle(), Credential.GetLength(), false);
        }

        internal CredentialMarshalUnknown(SafeCredBuffer credential, CredMarshalType cred_type) : base(cred_type)
        {
            Credential = credential;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="credential">The credential to marshal.</param>
        /// <param name="cred_type">The type of credential.</param>
        /// <remarks>This class doesn't take a reference to the buffer, it must remain valid over the lifetime of the call.</remarks>
        public CredentialMarshalUnknown(SafeBuffer credential, CredMarshalType cred_type) : base(cred_type)
        {
            Credential = new SafeHGlobalBuffer(credential.DangerousGetHandle(), credential.GetLength(), false);
        }
    }
}
