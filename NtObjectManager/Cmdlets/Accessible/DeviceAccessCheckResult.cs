//  Copyright 2017 Google Inc. All Rights Reserved.
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

using NtCoreLib;
using NtCoreLib.Security.Authorization;

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// <para type="description">Access check result for a device.</para>
/// </summary>
public class DeviceAccessCheckResult : CommonAccessCheckResult
{
    /// <summary>
    /// Indicates this was a namespace open
    /// </summary>
    public bool NamespacePath { get; }

    /// <summary>
    /// Indicates the type of device.
    /// </summary>
    public FileDeviceType DeviceType { get; }

    /// <summary>
    /// Indicates the device characteristics.
    /// </summary>
    public FileDeviceCharacteristics Characteristics { get; }

    internal DeviceAccessCheckResult(string name, bool namespace_path, FileDeviceType device_type, FileDeviceCharacteristics device_chars,
        AccessMask granted_access, SecurityDescriptor sd, TokenInformation token_info) : base(name, "Device",
            granted_access, NtType.GetTypeByType<NtFile>().GenericMapping, sd, typeof(FileAccessRights), true, token_info)
    {
        NamespacePath = namespace_path;
        DeviceType = device_type;
        Characteristics = device_chars;
    }
}
