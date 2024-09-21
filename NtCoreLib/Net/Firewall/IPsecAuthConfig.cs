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

using NtCoreLib.Utilities.Reflection;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace NtCoreLib.Net.Firewall;

/// <summary>
/// IPsec auth config.
/// </summary>
public enum IPsecAuthConfig : byte
{
    [SDKName("IPSEC_AUTH_CONFIG_HMAC_MD5_96")]
    HMAC_MD5_96 = 0,
    [SDKName("IPSEC_AUTH_CONFIG_HMAC_SHA_1_96")]
    HMAC_SHA1_96 = 1,
    [SDKName("IPSEC_AUTH_CONFIG_HMAC_SHA_256_128")]
    HMAC_SHA256_128 = 2,
    [SDKName("IPSEC_AUTH_CONFIG_GCM_AES_128")]
    GCM_AES128 = 3,
    [SDKName("IPSEC_AUTH_CONFIG_GCM_AES_192")]
    GCM_AES192 = 4,
    [SDKName("IPSEC_AUTH_CONFIG_GCM_AES_256")]
    GCM_AES256 = 5,
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member