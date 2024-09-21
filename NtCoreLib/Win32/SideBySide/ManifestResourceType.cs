//  Copyright 2016, 2017 Google Inc. All Rights Reserved.
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

namespace NtCoreLib.Win32.SideBySide;

/// <summary>
/// Type of manifest, based on the resource ID.
/// </summary>
public enum ManifestResourceType
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    Unknown = 0,
    [SDKName("CREATEPROCESS_MANIFEST_RESOURCE_ID")]
    CreateProcess = 1,
    [SDKName("ISOLATIONAWARE_MANIFEST_RESOURCE_ID ")]
    IsolationAware = 2,
    [SDKName("ISOLATIONAWARE_NOSTATICIMPORT_MANIFEST_RESOURCE_ID")]
    IsolationAwareNoStaticImport = 3
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
