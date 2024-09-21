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

    internal CredentialMarshalUsernameTarget(USERNAME_TARGET_CREDENTIAL_INFO info, CredMarshalType cred_type) : base(cred_type)
    {
        UserName = info.UserName;
    }
}
