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

using NtCoreLib.Security.Authorization;
using NtCoreLib.Win32.Service;
using NtCoreLib.Win32.Service.Triggers;
using System.Collections.Generic;

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// <para type="description">Access check result for a service.</para>
/// </summary>
public class ServiceAccessCheckResult : CommonAccessCheckResult
{
    /// <summary>
    /// Service triggers for service.
    /// </summary>
    public IEnumerable<ServiceTriggerInformation> Triggers => Service.Triggers;

    /// <summary>
    /// Indicates additional access granted based on the Triggers.
    /// </summary>
    public ServiceAccessRights TriggerGrantedAccess { get; }

    /// <summary>
    /// Indicates original access granted without triggers.
    /// </summary>
    public ServiceAccessRights OriginalGrantedAccess { get; }

    /// <summary>
    /// Indicates the service information.
    /// </summary>
    public ServiceInstance Service { get; }

    /// <summary>
    /// Indicates the service image path.
    /// </summary>
    public string ImagePath => Service.ImagePath;

    /// <summary>
    /// Indicates the service DLL.
    /// </summary>
    public string ServiceDll => Service.ServiceDll;

    internal ServiceAccessCheckResult(string name, AccessMask granted_access, 
        SecurityDescriptor sd, TokenInformation token_info,
        ServiceAccessRights trigger_granted_access, 
        ServiceAccessRights original_granted_access,
        ServiceInstance service) 
        : base(name, ServiceUtils.SERVICE_NT_TYPE_NAME, granted_access,
            ServiceUtils.GetServiceGenericMapping(), sd, 
            typeof(ServiceAccessRights), false, token_info)
    {
        TriggerGrantedAccess = trigger_granted_access;
        OriginalGrantedAccess = original_granted_access;
        Service = service;
    }
}
