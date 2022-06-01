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
                    case CredMarshalType.UsernameForPackedCredentials:
                        return new CredentialMarshalUsernameTarget(buffer.ReadStructUnsafe<USERNAME_TARGET_CREDENTIAL_INFO>(), cred_type);
                    case CredMarshalType.BinaryBlobCredential:
                    case CredMarshalType.BinaryBlobForSystem:
                        return new CredentialMarshalBinaryBlob(buffer.ReadStructUnsafe<BINARY_BLOB_CREDENTIAL_INFO>(), cred_type);
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
}
