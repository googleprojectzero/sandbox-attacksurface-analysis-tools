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

#nullable enable

using NtCoreLib.Security.Authorization;
using NtCoreLib.Win32.Service.Interop;
using NtCoreLib.Win32.Service.Triggers;
using System;
using System.Collections.Generic;

namespace NtCoreLib.Win32.Service;

/// <summary>
/// Class representing a service instance including its current status and configuration.
/// </summary>
public sealed class ServiceInstance
{
    private readonly Lazy<ServiceConfig> _service_configuration;
    private readonly Lazy<SecurityDescriptor> _security_descriptor;

    private ServiceConfig GetServiceConfiguration()
    {
        return ServiceUtils.GetServiceConfiguration(MachineName, Name,
            false).GetResultOrDefault(new ServiceConfig(MachineName, Name));
    }

    private SecurityDescriptor GetServiceSecurityDescriptor()
    {
        return ServiceUtils.GetServiceSecurityDescriptor(MachineName, Name, 
            SafeServiceHandle.DEFAULT_SECURITY_INFORMATION, false).GetResultOrDefault();
    }

    /// <summary>
    /// The name of the service.
    /// </summary>
    public string Name { get; }
    /// <summary>
    /// The description of the service.
    /// </summary>
    public string DisplayName { get; }
    /// <summary>
    /// Type of service.
    /// </summary>
    public ServiceType ServiceType { get; }
    /// <summary>
    /// Image path for the service.
    /// </summary>
    public string ImagePath => _service_configuration.Value.ImagePath;
    /// <summary>
    /// Command line for the service.
    /// </summary>
    public string CommandLine => _service_configuration.Value.BinaryPathName;
    /// <summary>
    /// Service DLL if a shared process server.
    /// </summary>
    public string? ServiceDll => _service_configuration.Value.ServiceDll;
    /// <summary>
    /// Current service status.
    /// </summary>
    public ServiceStatus Status { get; }
    /// <summary>
    /// What controls are accepted by the service.
    /// </summary>
    public ServiceControlsAccepted ControlsAccepted { get; }
    /// <summary>
    /// Whether the service can be stopped.
    /// </summary>
    public bool CanStop => ControlsAccepted.HasFlagSet(ServiceControlsAccepted.Stop);
    /// <summary>
    /// The Win32 exit code.
    /// </summary>
    public Win32Error Win32ExitCode { get; }
    /// <summary>
    /// The service specific exit code, if Win32ExitCode is Win32Error.ERROR_SERVICE_SPECIFIC_ERROR.
    /// </summary>
    public int ServiceSpecificExitCode { get; }
    /// <summary>
    /// The checkpoint while starting.
    /// </summary>
    public int CheckPoint { get; }
    /// <summary>
    /// Waiting hint time.
    /// </summary>
    public int WaitHint { get; }
    /// <summary>
    /// Service flags.
    /// </summary>
    public ServiceFlags ServiceFlags { get; }
    /// <summary>
    /// Process ID of the running service.
    /// </summary>
    public int ProcessId { get; }
    /// <summary>
    /// The security descriptor of the service.
    /// </summary>
    public SecurityDescriptor SecurityDescriptor => _security_descriptor.Value;
    /// <summary>
    /// The list of triggers for the service.
    /// </summary>
    public IEnumerable<ServiceTriggerInformation> Triggers => _service_configuration.Value.Triggers;
    /// <summary>
    /// The service SID type.
    /// </summary>
    public ServiceSidType SidType => _service_configuration.Value.SidType;
    /// <summary>
    /// The service launch protected setting.
    /// </summary>
    public ServiceLaunchProtectedType LaunchProtected => _service_configuration.Value.LaunchProtected;
    /// <summary>
    /// The service required privileges.
    /// </summary>
    public IEnumerable<string> RequiredPrivileges => _service_configuration.Value.RequiredPrivileges;
    /// <summary>
    /// Service start type.
    /// </summary>
    public ServiceStartType StartType => _service_configuration.Value.StartType;
    /// <summary>
    /// Whether the service is a delayed auto start service.
    /// </summary>
    public bool DelayedAutoStart => _service_configuration.Value.DelayedAutoStart;
    /// <summary>
    /// Error control.
    /// </summary>
    public ServiceErrorControl ErrorControl => _service_configuration.Value.ErrorControl;
    /// <summary>
    /// Load order group.
    /// </summary>
    public string LoadOrderGroup => _service_configuration.Value.LoadOrderGroup;
    /// <summary>
    /// Tag ID for load order.
    /// </summary>
    public int TagId => _service_configuration.Value.TagId;
    /// <summary>
    /// Dependencies.
    /// </summary>
    public IEnumerable<string> Dependencies => _service_configuration.Value.Dependencies;
    /// <summary>
    /// The user name this service runs under.
    /// </summary>
    public string? UserName => _service_configuration.Value.UserName;
    /// <summary>
    /// Type of service host when using Win32Share.
    /// </summary>
    public string? ServiceHostType => _service_configuration.Value.ServiceHostType;
    /// <summary>
    /// Service main function when using Win32Share.
    /// </summary>
    public string? ServiceMain => _service_configuration.Value.ServiceMain;
    /// <summary>
    /// Indicates if this service process is grouped with others.
    /// </summary>
    public bool SvcHostSplitDisabled => _service_configuration.Value.SvcHostSplitDisabled;
    /// <summary>
    /// The name of the machine this service was found on.
    /// </summary>
    public string MachineName { get; }

    /// <summary>
    /// Overridden ToString method.
    /// </summary>
    /// <returns>The name of the service.</returns>
    public override string ToString()
    {
        return Name;
    }

    internal ServiceInstance(string name, string? display_name, string? machine_name, ServiceStatusProcess status)
    {
        Name = name;
        DisplayName = display_name ?? string.Empty;
        ServiceType = status.ServiceType;
        Status = status.CurrentState;
        ProcessId = status.ProcessId;
        ControlsAccepted = status.ControlsAccepted;
        Win32ExitCode = status.Win32ExitCode;
        ServiceSpecificExitCode = status.ServiceSpecificExitCode;
        CheckPoint = status.CheckPoint;
        WaitHint = status.WaitHint;
        ServiceFlags = status.ServiceFlags;
        MachineName = machine_name ?? string.Empty;
        _service_configuration = new Lazy<ServiceConfig>(GetServiceConfiguration);
        _security_descriptor = new Lazy<SecurityDescriptor>(GetServiceSecurityDescriptor);
    }

    internal ServiceInstance(string? machine_name, EnumServiceStatusProcess process)
        : this(process.Name, process.DisplayName, machine_name, process.Status)
    {
    }
}
#pragma warning restore

