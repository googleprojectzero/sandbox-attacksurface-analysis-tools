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
/// Revision for an image certificate.
/// </summary>
public enum ImageCertificateRevision : short
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    [SDKName("WIN_CERT_REVISION_1_0")]
    Revision1 = 0x0100,
    [SDKName("WIN_CERT_REVISION_2_0")]
    Revision2 = 0x0200
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}