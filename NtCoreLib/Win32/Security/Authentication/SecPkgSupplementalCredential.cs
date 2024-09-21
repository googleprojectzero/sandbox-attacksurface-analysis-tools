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

namespace NtCoreLib.Win32.Security.Authentication;

/// <summary>
/// Class to represent a supplemental credential.
/// </summary>
public sealed class SecPkgSupplementalCredential
{
    private readonly byte[] _credentials;

    /// <summary>
    /// The name of the package to use the credentials.
    /// </summary>
    public string PackageName { get; }

    /// <summary>
    /// The list of credentials.
    /// </summary>
    public byte[] Credentials => _credentials.CloneBytes();

    /// <summary>
    /// Parse the credentials for the NTLM OWF hash.
    /// </summary>
    /// <returns>The NTLM OWF hash. Returns null if not present.</returns>
    public byte[] GetNtlmOwfHash()
    {
        if (!AuthenticationPackage.CheckNtlm(PackageName))
            return null;
        if (_credentials.Length != 40)
            return null;
        BinaryReader reader = new(new MemoryStream(_credentials));
        // Version.
        if (reader.ReadInt32() != 0)
            return null;
        var flags = reader.ReadInt32();
        // NtPassword not valid.
        if ((flags & 2) == 0)
            return null;
        // LmPassword.
        reader.ReadBytes(16);
        return reader.ReadBytes(16);
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="package_name">The name of the package to use the credentials.</param>
    /// <param name="credentials">The list of credentials.</param>
    public SecPkgSupplementalCredential(string package_name, byte[] credentials)
    {
        if (string.IsNullOrEmpty(package_name))
        {
            throw new ArgumentException($"'{nameof(package_name)}' cannot be null or empty.", nameof(package_name));
        }

        if (credentials is null)
        {
            throw new ArgumentNullException(nameof(credentials));
        }

        PackageName = package_name;
        _credentials = credentials;
    }
}
