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

namespace NtCoreLib.Win32.Security.Credential;

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
