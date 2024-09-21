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

using NtCoreLib.Win32.Service.Interop;

#nullable enable

namespace NtCoreLib.Win32.Service;

/// <summary>
/// Class to represent service status when enumerated.
/// </summary>
public sealed class EnumServiceStatusProcess
{
    /// <summary>
    /// The name of the service.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// The display name of the service.
    /// </summary>
    public string DisplayName { get; }

    /// <summary>
    /// The service status.
    /// </summary>
    public ServiceStatusProcess Status { get; }

    internal EnumServiceStatusProcess(ENUM_SERVICE_STATUS_PROCESS status)
    {
        Name = status.lpServiceName.GetString() ?? string.Empty;
        DisplayName = status.lpDisplayName.GetString() ?? string.Empty;
        Status = new ServiceStatusProcess(status.ServiceStatusProcess);
    }
}
