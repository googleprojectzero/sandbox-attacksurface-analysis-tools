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
    [SDKName("IKEEXT_AUTHENTICATION_METHOD_TYPE")]
    public enum IkeExtAuthenticationMethodType
    {
        [SDKName("IKEEXT_PRESHARED_KEY")]
        PreSharedKey = 0,
        [SDKName("IKEEXT_CERTIFICATE")]
        Certificate = (PreSharedKey + 1),
        [SDKName("IKEEXT_KERBEROS")]
        Kerberos = (Certificate + 1),
        [SDKName("IKEEXT_ANONYMOUS")]
        Anonymous = (Kerberos + 1),
        [SDKName("IKEEXT_SSL")]
        Ssl = (Anonymous + 1),
        [SDKName("IKEEXT_NTLM_V2")]
        NtlmV2 = (Ssl + 1),
        [SDKName("IKEEXT_IPV6_CGA")]
        IPv6Cga = (NtlmV2 + 1),
        [SDKName("IKEEXT_CERTIFICATE_ECDSA_P256")]
        CertificateECDSA_P256 = (IPv6Cga + 1),
        [SDKName("IKEEXT_CERTIFICATE_ECDSA_P384")]
        CertificateECDSA_P384 = (CertificateECDSA_P256 + 1),
        [SDKName("IKEEXT_SSL_ECDSA_P256")]
        SslECDSA_P256 = (CertificateECDSA_P384 + 1),
        [SDKName("IKEEXT_SSL_ECDSA_P384")]
        SslECDSA_P384 = (SslECDSA_P256 + 1),
        [SDKName("IKEEXT_EAP")]
        EAP = (SslECDSA_P384 + 1),
        [SDKName("IKEEXT_RESERVED")]
        Reserved = (EAP + 1),
    }
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member