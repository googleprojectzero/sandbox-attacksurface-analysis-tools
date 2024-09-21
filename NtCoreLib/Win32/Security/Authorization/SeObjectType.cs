//  Copyright 2020 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Win32.Security.Authorization
{
#pragma warning disable 1591
    /// <summary>
    /// Enumeration for object type.
    /// </summary>
    public enum SeObjectType
    {
        [SDKName("SE_UNKNOWN_OBJECT_TYPE")]
        Unknown = 0,
        [SDKName("SE_FILE_OBJECT")]
        File,
        [SDKName("SE_SERVICE")]
        Service,
        [SDKName("SE_PRINTER")]
        Printer,
        [SDKName("SE_REGISTRY_KEY")]
        RegistryKey,
        [SDKName("SE_LMSHARE")]
        LMShare,
        [SDKName("SE_KERNEL_OBJECT")]
        Kernel,
        [SDKName("SE_WINDOW_OBJECT")]
        Window,
        [SDKName("SE_DS_OBJECT")]
        Ds,
        [SDKName("SE_DS_OBJECT_ALL")]
        DsAll,
        [SDKName("SE_PROVIDER_DEFINED_OBJECT")]
        ProviderDefined,
        [SDKName("SE_WMIGUID_OBJECT")]
        WmiGuid,
        [SDKName("SE_REGISTRY_WOW64_32KEY")]
        RegistryWow6432Key,
        [SDKName("SE_REGISTRY_WOW64_64KEY")]
        RegistryWow6464Key
    }
}
