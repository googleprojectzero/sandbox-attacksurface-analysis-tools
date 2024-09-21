//  Copyright 2021 Google LLC. All Rights Reserved.
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

using NtApiDotNet.Utilities.Reflection;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// IPsec Cipher Configuration.
    /// </summary>
    public enum IPsecCipherConfig : byte
    {
        [SDKName("IPSEC_CIPHER_CONFIG_CBC_DES")]
        CBC_DES = 1,
        [SDKName("IPSEC_CIPHER_CONFIG_CBC_3DES")]
        CBC_3DES = 2,
        [SDKName("IPSEC_CIPHER_CONFIG_CBC_AES_128")]
        CBC_AES128 = 3,
        [SDKName("IPSEC_CIPHER_CONFIG_CBC_AES_192")]
        CBC_AES192 = 4,
        [SDKName("IPSEC_CIPHER_CONFIG_CBC_AES_256")]
        CBC_AES256 = 5,
        [SDKName("IPSEC_CIPHER_CONFIG_GCM_AES_128")]
        GCM_AES128 = 6,
        [SDKName("IPSEC_CIPHER_CONFIG_GCM_AES_192")]
        GCM_AES192 = 7,
        [SDKName("IPSEC_CIPHER_CONFIG_GCM_AES_256")]
        GCM_AES256 = 8,
    }
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member