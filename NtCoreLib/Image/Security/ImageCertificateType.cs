//  Copyright 2018 Google Inc. All Rights Reserved.
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

namespace NtCoreLib.Image.Security;

/// <summary>
/// Type for an image certificate.
/// </summary>
public enum ImageCertificateType : ushort
{
    [SDKName("WIN_CERT_TYPE_X509")]
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    X509 = 1,
    [SDKName("WIN_CERT_TYPE_PKCS_SIGNED_DATA")]
    PkcsSignedData = 2,
    [SDKName("WIN_CERT_TYPE_RESERVED_1")]
    Reserved1 = 3,
    [SDKName("WIN_CERT_TYPE_TS_STACK_SIGNED")]
    TsStackSigned = 4,
    [SDKName("WIN_CERT_TYPE_ANY")]
    Any = 255,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
