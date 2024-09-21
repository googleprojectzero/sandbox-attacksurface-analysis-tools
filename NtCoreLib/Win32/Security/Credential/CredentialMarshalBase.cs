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

using NtCoreLib.Win32.Security.Interop;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Security.Credential;

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
            return cred_type switch
            {
                CredMarshalType.CertCredential => new CredentialMarshalCertificate(buffer.ReadStructUnsafe<CERT_CREDENTIAL_INFO>()),
                CredMarshalType.UsernameTargetCredential or CredMarshalType.UsernameForPackedCredentials => new CredentialMarshalUsernameTarget(buffer.ReadStructUnsafe<USERNAME_TARGET_CREDENTIAL_INFO>(), cred_type),
                CredMarshalType.BinaryBlobCredential or CredMarshalType.BinaryBlobForSystem => new CredentialMarshalBinaryBlob(buffer.ReadStructUnsafe<BINARY_BLOB_CREDENTIAL_INFO>(), cred_type),
                _ => new CredentialMarshalUnknown(buffer.Detach(), cred_type),
            };
        }
    }

    private protected CredentialMarshalBase(CredMarshalType cred_type)
    {
        CredType = cred_type;
    }
}
