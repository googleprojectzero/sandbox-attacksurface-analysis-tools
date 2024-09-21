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
        Blob = blob.CloneBytes();
    }

    internal override SafeBuffer ToBuffer()
    {
        using var buffer = new SafeStructureInOutBuffer<BINARY_BLOB_CREDENTIAL_INFO>(Blob.Length, true);
        var data = buffer.Data;
        data.WriteBytes(Blob);
        buffer.Result = new BINARY_BLOB_CREDENTIAL_INFO
        {
            cbBlob = Blob.Length,
            pbBlob = data.DangerousGetHandle()
        };
        return buffer.Detach();
    }

    internal CredentialMarshalBinaryBlob(BINARY_BLOB_CREDENTIAL_INFO info, CredMarshalType marshal_type) : base(marshal_type)
    {
        Blob = new byte[info.cbBlob];
        Marshal.Copy(info.pbBlob, Blob, 0, info.cbBlob);
    }
}
