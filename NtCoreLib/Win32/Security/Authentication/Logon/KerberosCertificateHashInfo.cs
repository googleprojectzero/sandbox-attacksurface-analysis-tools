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

using System;
using System.IO;
using System.Text;

namespace NtCoreLib.Win32.Security.Authentication.Logon;

/// <summary>
/// Class to represent the KERB_CERTIFICATE_HASHINFO CSP data.
/// </summary>
public sealed class KerberosCertificateHashInfo : KerberosCertificateLogonData
{
    /// <summary>
    /// The name of the store.
    /// </summary>
    public string StoreName { get; set; }

    /// <summary>
    /// The certificate hash.
    /// </summary>
    public byte[] Hash { get; set; }

    internal override byte[] GetData()
    {
        if (Hash is null)
            throw new ArgumentNullException(nameof(Hash));
        MemoryStream stm = new();
        BinaryWriter writer = new(stm);
        byte[] name = Array.Empty<byte>();
        if (!(StoreName is null))
        {
            name = Encoding.Unicode.GetBytes(StoreName + "\0");
        }
        writer.Write((ushort)name.Length);
        writer.Write((ushort)Hash.Length);
        writer.Write(name);
        writer.Write(Hash);
        return stm.ToArray();
    }

    internal override int GetLogonType()
    {
        // KERB_CERTIFICATE_INFO_TYPE::CertHashInfo = 1
        return 1;
    }
}
