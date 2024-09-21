//  Copyright 2021 Google Inc. All Rights Reserved.
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

namespace NtCoreLib.Win32.Security.Authentication;

/// <summary>
/// Class to represent the key information for an authentication context's session key.
/// </summary>
public sealed class AuthenticationContextKeyInfo
{
    /// <summary>
    /// The name of the signature algorithm.
    /// </summary>
    public string SignatureAlgorithmName { get; }
    /// <summary>
    /// The name of the encryption algorithm.
    /// </summary>
    public string EncryptAlgorithmName { get; }
    /// <summary>
    /// The size of the session key.
    /// </summary>
    public int KeySize { get; }
    /// <summary>
    /// The signature algorithm ID.
    /// </summary>
    /// <remarks>The value depends on the package, e.g. for Kerberos it's the keytype</remarks>
    public int SignatureAlgorithm { get; }
    /// <summary>
    /// The encryption algorithm ID.
    /// </summary>
    public int EncryptAlgorithm { get; }

    internal AuthenticationContextKeyInfo(SecPkgContext_KeyInfo key_info)
    {
        SignatureAlgorithmName = key_info.SignatureAlgorithmName;
        EncryptAlgorithmName = key_info.EncryptAlgorithmName;
        KeySize = key_info.KeySize;
        SignatureAlgorithm = key_info.SignatureAlgorithm;
        EncryptAlgorithm = key_info.EncryptAlgorithm;
    }
}
