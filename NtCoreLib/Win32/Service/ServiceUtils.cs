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

using NtCoreLib.Security;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Win32.Service.Interop;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace NtCoreLib.Win32.Service;

#pragma warning restore
/// <summary>
/// Utilities for accessing services.
/// </summary>
public static class ServiceUtils
{
    #region Private Members
    internal static string GetString(this IntPtr ptr)
    {
        if (ptr != IntPtr.Zero)
            return Marshal.PtrToStringUni(ptr);
        return string.Empty;
    }

    internal static IEnumerable<string> GetMultiString(this IntPtr ptr)
    {
        List<string> ss = new();
        if (ptr == IntPtr.Zero)
            return new string[0];
        string s = ptr.GetString();
        while (s.Length > 0)
        {
            ss.Add(s);
            ptr += (s.Length + 1) * 2;
            s = ptr.GetString();
        }
        return ss.AsReadOnly();
    }

    internal static string? ToMultiString(this IEnumerable<string>? ss)
    {
        if (ss == null || !ss.Any())
            return null;

        StringBuilder builder = new();

        foreach (var s in ss)
        {
            builder.Append(s);
            builder.Append('\0');
        }
        builder.Append('\0');
        return builder.ToString();
    }

    private static string GetServiceDisplayName(Service service)
    {
        return service.QueryDisplayName(false).GetResultOrDefault(string.Empty);
    }

    private static ServiceStatusProcess QueryStatus(Service service)
    {
        return service.QueryStatus(false).GetResultOrDefault();
    }

    private static NtResult<ServiceControlManager> OpenSCManager(string? machine_name, ServiceControlManagerAccessRights desired_access, bool throw_on_error)
    {
        return ServiceControlManager.Open(machine_name, null, desired_access | ServiceControlManagerAccessRights.Connect, throw_on_error);
    }

    private static NtResult<ServiceControlManager> OpenSCManager(string? machine_name, bool throw_on_error)
    {
        return OpenSCManager(machine_name, 0, throw_on_error);
    }

    private static NtResult<Service> OpenService(ServiceControlManager scm, string name, ServiceAccessRights desired_access, bool throw_on_error)
    {
        return scm.OpenService(name, desired_access, throw_on_error);
    }

    private static NtResult<Service> OpenService(string? machine_name, string name, ServiceAccessRights desired_access, bool throw_on_error)
    {
        using var scm = OpenSCManager(machine_name, throw_on_error);
        if (!scm.IsSuccess)
            return scm.Cast<Service>();

        return OpenService(scm.Result, name, desired_access, throw_on_error);
    }

    private static ServiceAccessRights ControlCodeToAccess(ServiceControlCode control_code)
    {
        switch (control_code)
        {
            case ServiceControlCode.Stop:
                return ServiceAccessRights.Stop;
            case ServiceControlCode.Continue:
            case ServiceControlCode.Pause:
            case ServiceControlCode.ParamChange:
            case ServiceControlCode.NetBindAdd:
            case ServiceControlCode.NetBindDisable:
            case ServiceControlCode.NetBindEnable:
            case ServiceControlCode.NetBindRemove:
                return ServiceAccessRights.PauseContinue;
            case ServiceControlCode.Interrogate:
                return ServiceAccessRights.Interrogate;
            default:
                if ((int)control_code >= 128)
                    return ServiceAccessRights.UserDefinedControl;
                return ServiceAccessRights.All;
        }
    }
    #endregion

    #region Static Properties
    /// <summary>
    /// The name of the fake NT type for a service.
    /// </summary>
    public const string SERVICE_NT_TYPE_NAME = "Service";
    /// <summary>
    /// The name of the fake NT type for the SCM.
    /// </summary>
    public const string SCM_NT_TYPE_NAME = "SCM";
    #endregion

    #region Static Methods
    /// <summary>
    /// Get the generic mapping for the SCM.
    /// </summary>
    /// <returns>The SCM generic mapping.</returns>
    public static GenericMapping GetScmGenericMapping()
    {
        GenericMapping mapping = new()
        {
            GenericRead = ServiceControlManagerAccessRights.ReadControl | ServiceControlManagerAccessRights.EnumerateService | ServiceControlManagerAccessRights.QueryLockStatus,
            GenericWrite = ServiceControlManagerAccessRights.ReadControl | ServiceControlManagerAccessRights.CreateService | ServiceControlManagerAccessRights.ModifyBootConfig,
            GenericExecute = ServiceControlManagerAccessRights.ReadControl | ServiceControlManagerAccessRights.Connect | ServiceControlManagerAccessRights.Lock,
            GenericAll = ServiceControlManagerAccessRights.All
        };
        return mapping;
    }

    /// <summary>
    /// Get the generic mapping for a service.
    /// </summary>
    /// <returns>The service generic mapping.</returns>
    public static GenericMapping GetServiceGenericMapping()
    {
        GenericMapping mapping = new()
        {
            GenericRead = ServiceAccessRights.ReadControl | ServiceAccessRights.QueryConfig
            | ServiceAccessRights.QueryStatus | ServiceAccessRights.Interrogate | ServiceAccessRights.EnumerateDependents,
            GenericWrite = ServiceAccessRights.ReadControl | ServiceAccessRights.ChangeConfig,
            GenericExecute = ServiceAccessRights.ReadControl | ServiceAccessRights.Start
            | ServiceAccessRights.Stop | ServiceAccessRights.PauseContinue | ServiceAccessRights.UserDefinedControl,
            GenericAll = ServiceAccessRights.All
        };
        return mapping;
    }

    /// <summary>
    /// Get the security descriptor of the SCM.
    /// </summary>
    /// <returns>The SCM security descriptor.</returns>
    public static SecurityDescriptor GetScmSecurityDescriptor()
    {
        return GetScmSecurityDescriptor(SafeServiceHandle.DEFAULT_SECURITY_INFORMATION);
    }

    /// <summary>
    /// Get the security descriptor of the SCM.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="security_information">Parts of the security descriptor to return.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The SCM security descriptor.</returns>
    public static NtResult<SecurityDescriptor> GetScmSecurityDescriptor(string? machine_name, SecurityInformation security_information, bool throw_on_error)
    {
        var desired_access = NtSecurity.QuerySecurityAccessMask(security_information).ToSpecificAccess<ServiceControlManagerAccessRights>();
        using var scm = ServiceControlManager.Open(machine_name, null, desired_access, throw_on_error);
        if (!scm.IsSuccess)
            return scm.Cast<SecurityDescriptor>();
        return scm.Result.GetSecurityDescriptor(security_information, throw_on_error);
    }

    /// <summary>
    /// Get the security descriptor of the SCM.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="security_information">Parts of the security descriptor to return.</param>
    /// <returns>The SCM security descriptor.</returns>
    public static SecurityDescriptor GetScmSecurityDescriptor(string? machine_name, SecurityInformation security_information)
    {
        return GetScmSecurityDescriptor(machine_name, security_information, true).Result;
    }

    /// <summary>
    /// Get the security descriptor of the SCM.
    /// </summary>
    /// <param name="security_information">Parts of the security descriptor to return.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The SCM security descriptor.</returns>
    public static NtResult<SecurityDescriptor> GetScmSecurityDescriptor(SecurityInformation security_information, bool throw_on_error)
    {
        return GetScmSecurityDescriptor(null, security_information, throw_on_error);
    }

    /// <summary>
    /// Get the security descriptor of the SCM.
    /// </summary>
    /// <param name="security_information">Parts of the security descriptor to return.</param>
    /// <returns>The SCM security descriptor.</returns>
    public static SecurityDescriptor GetScmSecurityDescriptor(SecurityInformation security_information)
    {
        return GetScmSecurityDescriptor(security_information, true).Result;
    }

    /// <summary>
    /// Get the security descriptor for a service.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="security_information">Parts of the security descriptor to return.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <returns>The security descriptor.</returns>
    public static NtResult<SecurityDescriptor> GetServiceSecurityDescriptor(
        string? machine_name, string name, SecurityInformation security_information, bool throw_on_error)
    {
        var desired_access = NtSecurity.QuerySecurityAccessMask(security_information).ToSpecificAccess<ServiceAccessRights>();
        using var service = OpenService(machine_name, name, desired_access, throw_on_error);
        if (!service.IsSuccess)
            return service.Cast<SecurityDescriptor>();
        return service.Result.GetSecurityDescriptor(security_information, throw_on_error);
    }

    /// <summary>
    /// Get the security descriptor for a service.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="security_information">Parts of the security descriptor to return.</param>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <returns>The security descriptor.</returns>
    public static SecurityDescriptor GetServiceSecurityDescriptor(
        string? machine_name, string name, SecurityInformation security_information)
    {
        return GetServiceSecurityDescriptor(machine_name, name, security_information, true).Result;
    }

    /// <summary>
    /// Get the security descriptor for a service.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="security_information">Parts of the security descriptor to return.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The security descriptor.</returns>
    public static NtResult<SecurityDescriptor> GetServiceSecurityDescriptor(string name,
        SecurityInformation security_information, bool throw_on_error)
    {
        return GetServiceSecurityDescriptor(null, name, security_information, throw_on_error);
    }

    /// <summary>
    /// Get the security descriptor for a service.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="security_information">Parts of the security descriptor to return.</param>
    /// <returns>The security descriptor.</returns>
    public static SecurityDescriptor GetServiceSecurityDescriptor(string name,
        SecurityInformation security_information)
    {
        return GetServiceSecurityDescriptor(name, security_information, true).Result;
    }

    /// <summary>
    /// Set the SCM security descriptor.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="security_descriptor">The security descriptor to set.</param>
    /// <param name="security_information">The parts of the security descriptor to set.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus SetScmSecurityDescriptor(string? machine_name, SecurityDescriptor security_descriptor,
        SecurityInformation security_information, bool throw_on_error)
    {
        var desired_access = NtSecurity.SetSecurityAccessMask(security_information).ToSpecificAccess<ServiceControlManagerAccessRights>();
        using var scm = OpenSCManager(machine_name, desired_access, throw_on_error);
        if (!scm.IsSuccess)
            return scm.Status;
        return scm.Result.SetSecurityDescriptor(security_descriptor, security_information, throw_on_error);
    }

    /// <summary>
    /// Set the SCM security descriptor.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="security_descriptor">The security descriptor to set.</param>
    /// <param name="security_information">The parts of the security descriptor to set.</param>
    public static void SetScmSecurityDescriptor(string? machine_name, SecurityDescriptor security_descriptor,
        SecurityInformation security_information)
    {
        SetScmSecurityDescriptor(machine_name, security_descriptor, security_information, true);
    }

    /// <summary>
    /// Set the SCM security descriptor.
    /// </summary>
    /// <param name="security_descriptor">The security descriptor to set.</param>
    /// <param name="security_information">The parts of the security descriptor to set.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus SetScmSecurityDescriptor(SecurityDescriptor security_descriptor,
        SecurityInformation security_information, bool throw_on_error)
    {
        return SetScmSecurityDescriptor(null, security_descriptor, security_information, throw_on_error);
    }

    /// <summary>
    /// Set the SCM security descriptor.
    /// </summary>
    /// <param name="security_descriptor">The security descriptor to set.</param>
    /// <param name="security_information">The parts of the security descriptor to set.</param>
    public static void SetScmSecurityDescriptor(SecurityDescriptor security_descriptor,
        SecurityInformation security_information)
    {
        SetScmSecurityDescriptor(security_descriptor, security_information, true);
    }

    /// <summary>
    /// Get the information about a service.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The service information.</returns>
    public static NtResult<ServiceConfig> GetServiceConfiguration(string? machine_name, string name, bool throw_on_error)
    {
        using var service = OpenService(machine_name, name, ServiceAccessRights.QueryConfig, throw_on_error);
        if (!service.IsSuccess)
            return service.Cast<ServiceConfig>();
        return service.Result.QueryConfig(throw_on_error);
    }

    /// <summary>
    /// Get the information about a service.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <returns>The service information.</returns>
    public static ServiceConfig GetServiceConfiguration(string? machine_name, string name)
    {
        return GetServiceConfiguration(machine_name, name, true).Result;
    }

    /// <summary>
    /// Get the information about a service.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The service information.</returns>
    public static NtResult<ServiceConfig> GetServiceConfiguration(string name, bool throw_on_error)
    {
        return GetServiceConfiguration(null, name, throw_on_error);
    }

    /// <summary>
    /// Set the security descriptor for a service.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="security_descriptor">The security descriptor to set.</param>
    /// <param name="security_information">The security information to set.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status.</returns>
    public static NtStatus SetServiceSecurityDescriptor(string? machine_name,
        string name, SecurityDescriptor security_descriptor, SecurityInformation security_information, bool throw_on_error)
    {
        var desired_access = NtSecurity.SetSecurityAccessMask(security_information).ToSpecificAccess<ServiceAccessRights>();
        using var service = OpenService(machine_name, name, desired_access, throw_on_error);
        if (!service.IsSuccess)
            return service.Status;
        return service.Result.SetSecurityDescriptor(security_descriptor, security_information, throw_on_error);
    }

    /// <summary>
    /// Set the security descriptor for a service.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="security_descriptor">The security descriptor to set.</param>
    /// <param name="security_information">The security information to set.</param>
    public static void SetServiceSecurityDescriptor(string? machine_name,
        string name, SecurityDescriptor security_descriptor, SecurityInformation security_information)
    {
        SetServiceSecurityDescriptor(machine_name, name, security_descriptor, security_information, true);
    }

    /// <summary>
    /// Set the security descriptor for a service.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="security_descriptor">The security descriptor to set.</param>
    /// <param name="security_information">The security information to set.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status.</returns>
    public static NtStatus SetServiceSecurityDescriptor(string name, SecurityDescriptor security_descriptor,
        SecurityInformation security_information, bool throw_on_error)
    {
        return SetServiceSecurityDescriptor(null, name, security_descriptor, security_information, throw_on_error);
    }

    /// <summary>
    /// Set the security descriptor for a service.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="security_descriptor">The security descriptor to set.</param>
    /// <param name="security_information">The security information to set.</param>
    public static void SetServiceSecurityDescriptor(string name, SecurityDescriptor security_descriptor,
        SecurityInformation security_information)
    {
        SetServiceSecurityDescriptor(name, security_descriptor, security_information, true);
    }

    /// <summary>
    /// Get the information about a service.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <returns>The service information.</returns>
    public static ServiceConfig GetServiceConfiguration(string name)
    {
        return GetServiceConfiguration(name, true).Result;
    }

    /// <summary>
    /// Get the information about all services.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="service_types">The types of services to return.</param>
    /// <returns>The list of service information.</returns>
    public static IEnumerable<ServiceConfig> GetServiceConfiguration(string? machine_name, ServiceType service_types)
    {
        return GetServices(machine_name, ServiceState.All, service_types).Select(s => GetServiceConfiguration(s.Name,
            false).GetResultOrDefault()).Where(s => s != null && s.ServiceType.HasFlagSet(service_types)).ToArray();
    }

    /// <summary>
    /// Get the information about all services.
    /// </summary>
    /// <param name="service_types">The types of services to return.</param>
    /// <returns>The list of service information.</returns>
    public static IEnumerable<ServiceConfig> GetServiceConfiguration(ServiceType service_types)
    {
        return GetServiceConfiguration(null, service_types);
    }

    /// <summary>
    /// Get the PID of a running service.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <returns>Returns the PID of the running service, or 0 if not running.</returns>
    /// <exception cref="NtException">Thrown on error.</exception>
    public static int GetServiceProcessId(string name)
    {
        using var service = OpenService(string.Empty, name, ServiceAccessRights.QueryStatus, true).Result;
        return service.Status.ProcessId;
    }

    /// <summary>
    /// Get a running service by name.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The running service.</returns>
    /// <remarks>This will return active and non-active services as well as drivers.</remarks>
    public static NtResult<ServiceInstance> GetService(string? machine_name, string name, bool throw_on_error)
    {
        using var service = OpenService(machine_name, name, ServiceAccessRights.QueryConfig | ServiceAccessRights.QueryStatus, throw_on_error);
        if (!service.IsSuccess)
            return service.Cast<ServiceInstance>();
        return new ServiceInstance(name, GetServiceDisplayName(service.Result), machine_name, QueryStatus(service.Result)).CreateResult();
    }

    /// <summary>
    /// Get a running service by name.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <returns>The running service.</returns>
    /// <remarks>This will return active and non-active services as well as drivers.</remarks>
    public static ServiceInstance GetService(string? machine_name, string name)
    {
        return GetService(machine_name, name, true).Result;
    }

    /// <summary>
    /// Get a running service by name.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <returns>The running service.</returns>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <remarks>This will return active and non-active services as well as drivers.</remarks>
    public static NtResult<ServiceInstance> GetService(string name, bool throw_on_error)
    {
        return GetService(null, name, throw_on_error);
    }

    /// <summary>
    /// Get a running service by name.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <returns>The running service.</returns>
    /// <remarks>This will return active and non-active services as well as drivers.</remarks>
    public static ServiceInstance GetService(string name)
    {
        return GetService(null, name, true).Result;
    }

    /// <summary>
    /// Get a list of all registered services.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="state">Specify state of services to get.</param>
    /// <param name="service_types">Specify the type filter for services.</param>
    /// <returns>A list of registered services.</returns>
    public static IEnumerable<ServiceInstance> GetServices(string? machine_name, ServiceState state, ServiceType service_types)
    {
        using var scm = OpenSCManager(machine_name, ServiceControlManagerAccessRights.EnumerateService, true).Result;
        return scm.EnumerateServiceStatus(state, service_types).Select(s => new ServiceInstance(machine_name, s)).ToList().AsReadOnly();
    }

    /// <summary>
    /// Get a list of all registered services.
    /// </summary>
    /// <param name="state">Specify state of services to get.</param>
    /// <param name="service_types">Specify the type filter for services.</param>
    /// <returns>A list of registered services.</returns>
    public static IEnumerable<ServiceInstance> GetServices(ServiceState state, ServiceType service_types)
    {
        return GetServices(null, state, service_types);
    }

    /// <summary>
    /// Get flags for all user service types.
    /// </summary>
    /// <returns>The flags for user service types.</returns>
    public static ServiceType GetServiceTypes()
    {
        ServiceType service_types = ServiceType.Win32OwnProcess | ServiceType.Win32ShareProcess;
        if (!NtObjectUtils.IsWindows81OrLess)
        {
            service_types |= ServiceType.UserService;
        }
        return service_types;
    }

    /// <summary>
    /// Get flags for all kernel driver types.
    /// </summary>
    /// <returns>The flags for kernel driver types.</returns>
    public static ServiceType GetDriverTypes()
    {
        return ServiceType.Driver;
    }

    /// <summary>
    /// Get a list of all registered services.
    /// </summary>
    /// <returns>A list of registered services.</returns>
    public static IEnumerable<ServiceInstance> GetServices()
    {
        return GetServices(null, ServiceState.All, GetServiceTypes());
    }

    /// <summary>
    /// Get a list of all active running services with their process IDs.
    /// </summary>
    /// <returns>A list of all active running services with process IDs.</returns>
    public static IEnumerable<ServiceInstance> GetRunningServicesWithProcessIds()
    {
        return GetServices(null, ServiceState.Active, GetServiceTypes());
    }

    /// <summary>
    /// Get a list of all drivers.
    /// </summary>
    /// <returns>A list of all drivers.</returns>
    public static IEnumerable<ServiceInstance> GetDrivers()
    {
        return GetServices(null, ServiceState.All, GetDriverTypes());
    }

    /// <summary>
    /// Get a list of all active running drivers.
    /// </summary>
    /// <returns>A list of all active running drivers.</returns>
    public static IEnumerable<ServiceInstance> GetRunningDrivers()
    {
        return GetServices(null, ServiceState.Active, GetDriverTypes());
    }

    /// <summary>
    /// Get a list of all services and drivers.
    /// </summary>
    /// <returns>A list of all services and drivers.</returns>
    public static IEnumerable<ServiceInstance> GetServicesAndDrivers()
    {
        return GetServices(null, ServiceState.All,
            GetDriverTypes() | GetServiceTypes());
    }

    /// <summary>
    /// Get a list of all services and drivers.
    /// </summary>
    /// <returns>A list of all services and drivers.</returns>
    public static IEnumerable<ServiceInstance> GetRunningServicesAndDrivers()
    {
        return GetServices(null, ServiceState.Active,
            GetDriverTypes() | GetServiceTypes());
    }

    /// <summary>
    /// Create a new service.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="name">The name of the service.</param>
    /// <param name="display_name">The display name for the service.</param>
    /// <param name="service_type">The service type.</param>
    /// <param name="start_type">The service start type.</param>
    /// <param name="error_control">Error control.</param>
    /// <param name="binary_path_name">Path to the service executable.</param>
    /// <param name="load_order_group">Load group order.</param>
    /// <param name="dependencies">List of service dependencies.</param>
    /// <param name="service_start_name">The username for the service.</param>
    /// <param name="password">Password for the username if needed.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The registered service information.</returns>
    public static NtResult<ServiceInstance> CreateService(
        string? machine_name,
        string name,
        string display_name,
        ServiceType service_type,
        ServiceStartType start_type,
        ServiceErrorControl error_control,
        string binary_path_name,
        string load_order_group,
        IEnumerable<string> dependencies,
        string service_start_name,
        SecureString password,
        bool throw_on_error)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException($"'{nameof(name)}' cannot be null or empty", nameof(name));
        }

        if (string.IsNullOrEmpty(binary_path_name))
        {
            throw new ArgumentException($"'{nameof(binary_path_name)}' cannot be null or empty", nameof(binary_path_name));
        }

        using var scm = OpenSCManager(machine_name, ServiceControlManagerAccessRights.Connect | ServiceControlManagerAccessRights.CreateService, throw_on_error);
        if (!scm.IsSuccess)
            return scm.Cast<ServiceInstance>();

        using var service = scm.Result.CreateService(name, display_name, ServiceAccessRights.MaximumAllowed, service_type,
            start_type, error_control, binary_path_name, load_order_group, dependencies, service_start_name, password, throw_on_error);
        return new ServiceInstance(name, display_name ?? string.Empty, machine_name,
            service.Result.QueryStatus(throw_on_error).GetResultOrDefault()).CreateResult();
    }

    /// <summary>
    /// Create a new service.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="name">The name of the service.</param>
    /// <param name="display_name">The display name for the service.</param>
    /// <param name="service_type">The service type.</param>
    /// <param name="start_type">The service start type.</param>
    /// <param name="error_control">Error control.</param>
    /// <param name="binary_path_name">Path to the service executable.</param>
    /// <param name="load_order_group">Load group order.</param>
    /// <param name="dependencies">List of service dependencies.</param>
    /// <param name="service_start_name">The username for the service.</param>
    /// <param name="password">Password for the username if needed.</param>
    /// <returns>The registered service information.</returns>
    public static ServiceInstance CreateService(
        string? machine_name,
        string name,
        string display_name,
        ServiceType service_type,
        ServiceStartType start_type,
        ServiceErrorControl error_control,
        string binary_path_name,
        string load_order_group,
        IEnumerable<string> dependencies,
        string service_start_name,
        SecureString password)
    {
        return CreateService(machine_name, name, display_name, service_type,
            start_type, error_control, binary_path_name, load_order_group,
            dependencies, service_start_name, password, true).Result;
    }

    /// <summary>
    /// Create a new service.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="display_name">The display name for the service.</param>
    /// <param name="service_type">The service type.</param>
    /// <param name="start_type">The service start type.</param>
    /// <param name="error_control">Error control.</param>
    /// <param name="binary_path_name">Path to the service executable.</param>
    /// <param name="load_order_group">Load group order.</param>
    /// <param name="dependencies">List of service dependencies.</param>
    /// <param name="service_start_name">The username for the service.</param>
    /// <param name="password">Password for the username if needed.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The registered service information.</returns>
    public static NtResult<ServiceInstance> CreateService(
        string name,
        string display_name,
        ServiceType service_type,
        ServiceStartType start_type,
        ServiceErrorControl error_control,
        string binary_path_name,
        string load_order_group,
        IEnumerable<string> dependencies,
        string service_start_name,
        SecureString password,
        bool throw_on_error)
    {
        return CreateService(null, name, display_name, service_type,
            start_type, error_control, binary_path_name, load_order_group,
            dependencies, service_start_name, password, throw_on_error);
    }

    /// <summary>
    /// Create a new service.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="display_name">The display name for the service.</param>
    /// <param name="service_type">The service type.</param>
    /// <param name="start_type">The service start type.</param>
    /// <param name="error_control">Error control.</param>
    /// <param name="binary_path_name">Path to the service executable.</param>
    /// <param name="load_order_group">Load group order.</param>
    /// <param name="dependencies">List of service dependencies.</param>
    /// <param name="service_start_name">The username for the service.</param>
    /// <param name="password">Password for the username if needed.</param>
    /// <returns>The registered service information.</returns>
    public static ServiceInstance CreateService(
        string name,
        string display_name,
        ServiceType service_type,
        ServiceStartType start_type,
        ServiceErrorControl error_control,
        string binary_path_name,
        string load_order_group,
        IEnumerable<string> dependencies,
        string service_start_name,
        SecureString password)
    {
        return CreateService(name, display_name, service_type,
            start_type, error_control, binary_path_name, load_order_group,
            dependencies, service_start_name, password, true).Result;
    }

    /// <summary>
    /// Delete a service.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="name">The name of the service.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status.</returns>
    public static NtStatus DeleteService(string? machine_name, string name, bool throw_on_error)
    {
        using var service = OpenService(machine_name, name, ServiceAccessRights.Delete, throw_on_error);
        if (!service.IsSuccess)
            return service.Status;
        return service.Result.Delete(throw_on_error);
    }

    /// <summary>
    /// Delete a service.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="name">The name of the service.</param>
    /// <returns>The NT status.</returns>
    public static void DeleteService(string? machine_name, string name)
    {
        DeleteService(machine_name, name, true);
    }

    /// <summary>
    /// Delete a service.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status.</returns>
    public static NtStatus DeleteService(string name, bool throw_on_error)
    {
        return DeleteService(null, name, throw_on_error);
    }

    /// <summary>
    /// Delete a service.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    public static void DeleteService(string name)
    {
        DeleteService(name, true);
    }

    /// <summary>
    /// Send a control code to a service.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="name">The name of the service.</param>
    /// <param name="control_code">The control code to send. If >= 128 will be sent as a custom control code.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus ControlService(string? machine_name, string name, ServiceControlCode control_code, bool throw_on_error)
    {
        ServiceAccessRights desired_access = ControlCodeToAccess(control_code);
        using var service = OpenService(machine_name, name, desired_access, throw_on_error);
        if (!service.IsSuccess)
            return service.Status;
        return service.Result.Control(control_code, throw_on_error).Status;
    }

    /// <summary>
    /// Send a control code to a service.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="name">The name of the service.</param>
    /// <param name="control_code">The control code to send. If >= 128 will be sent as a custom control code.</param>
    public static void ControlService(string? machine_name, string name, ServiceControlCode control_code)
    {
        ControlService(machine_name, name, control_code, true);
    }

    /// <summary>
    /// Send a control code to a service.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="name">The name of the service.</param>
    /// <param name="control_code">The control code to send. If >= 128 will be sent as a custom control code.</param>
    public static void ControlService(string? machine_name, string name, int control_code)
    {
        ControlService(machine_name, name, (ServiceControlCode)control_code, true);
    }

    /// <summary>
    /// Send a control code to a service.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="control_code">The control code to send. If >= 128 will be sent as a custom control code.</param>
    public static void ControlService(string name, ServiceControlCode control_code)
    {
        ControlService(null, name, control_code);
    }

    /// <summary>
    /// Send a control code to a service.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="control_code">The control code to send. If >= 128 will be sent as a custom control code.</param>
    public static void ControlService(string name, int control_code)
    {
        ControlService(null, name, control_code);
    }

    /// <summary>
    /// Change service configuration.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="name">The name of the service.</param>
    /// <param name="display_name">The display name for the service.</param>
    /// <param name="service_type">The service type.</param>
    /// <param name="start_type">The service start type.</param>
    /// <param name="error_control">Error control.</param>
    /// <param name="binary_path_name">Path to the service executable.</param>
    /// <param name="load_order_group">Load group order.</param>
    /// <param name="tag_id">The tag ID.</param>
    /// <param name="dependencies">List of service dependencies.</param>
    /// <param name="service_start_name">The username for the service.</param>
    /// <param name="password">Password for the username if needed.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus ChangeServiceConfig(
        string? machine_name,
        string name,
        string display_name,
        ServiceType? service_type,
        ServiceStartType? start_type,
        ServiceErrorControl? error_control,
        string binary_path_name,
        int? tag_id,
        string load_order_group,
        IEnumerable<string> dependencies,
        string service_start_name,
        SecureString password,
        bool throw_on_error)
    {
        using var service = OpenService(machine_name, name, ServiceAccessRights.ChangeConfig, throw_on_error);
        if (!service.IsSuccess)
            return service.Status;
        return service.Result.ChangeServiceConfig(display_name, service_type, start_type, 
            error_control, binary_path_name, tag_id, load_order_group, dependencies, 
            service_start_name, password, throw_on_error);
    }

    /// <summary>
    /// Change service configuration.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="name">The name of the service.</param>
    /// <param name="display_name">The display name for the service.</param>
    /// <param name="service_type">The service type.</param>
    /// <param name="start_type">The service start type.</param>
    /// <param name="error_control">Error control.</param>
    /// <param name="binary_path_name">Path to the service executable.</param>
    /// <param name="tag_id">The tag ID.</param>
    /// <param name="load_order_group">Load group order.</param>
    /// <param name="dependencies">List of service dependencies.</param>
    /// <param name="service_start_name">The username for the service.</param>
    /// <param name="password">Password for the username if needed.</param>
    public static void ChangeServiceConfig(
        string? machine_name,
        string name,
        string display_name,
        ServiceType? service_type,
        ServiceStartType? start_type,
        ServiceErrorControl? error_control,
        string binary_path_name,
        int? tag_id,
        string load_order_group,
        IEnumerable<string> dependencies,
        string service_start_name,
        SecureString password)
    {
        ChangeServiceConfig(machine_name, name, display_name, service_type, start_type, error_control,
            binary_path_name, tag_id, load_order_group, dependencies, service_start_name, password, true);
    }

    /// <summary>
    /// Change service configuration.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="display_name">The display name for the service.</param>
    /// <param name="service_type">The service type.</param>
    /// <param name="start_type">The service start type.</param>
    /// <param name="error_control">Error control.</param>
    /// <param name="binary_path_name">Path to the service executable.</param>
    /// <param name="tag_id">The tag ID.</param>
    /// <param name="load_order_group">Load group order.</param>
    /// <param name="dependencies">List of service dependencies.</param>
    /// <param name="service_start_name">The username for the service.</param>
    /// <param name="password">Password for the username if needed.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus ChangeServiceConfig(
        string name,
        string display_name,
        ServiceType? service_type,
        ServiceStartType? start_type,
        ServiceErrorControl? error_control,
        string binary_path_name,
        int? tag_id,
        string load_order_group,
        IEnumerable<string> dependencies,
        string service_start_name,
        SecureString password,
        bool throw_on_error)
    {
        return ChangeServiceConfig(null, name, display_name, service_type, start_type, error_control,
            binary_path_name, tag_id, load_order_group, dependencies, service_start_name, password, throw_on_error);
    }

    /// <summary>
    /// Change service configuration.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="display_name">The display name for the service.</param>
    /// <param name="service_type">The service type.</param>
    /// <param name="start_type">The service start type.</param>
    /// <param name="error_control">Error control.</param>
    /// <param name="binary_path_name">Path to the service executable.</param>
    /// <param name="tag_id">The tag ID.</param>
    /// <param name="load_order_group">Load group order.</param>
    /// <param name="dependencies">List of service dependencies.</param>
    /// <param name="service_start_name">The username for the service.</param>
    /// <param name="password">Password for the username if needed.</param>
    public static void ChangeServiceConfig(
        string name,
        string display_name,
        ServiceType? service_type,
        ServiceStartType? start_type,
        ServiceErrorControl? error_control,
        int? tag_id,
        string binary_path_name,
        string load_order_group,
        IEnumerable<string> dependencies,
        string service_start_name,
        SecureString password)
    {
        ChangeServiceConfig(null, name, display_name, service_type, start_type, error_control,
            binary_path_name, tag_id, load_order_group, dependencies, service_start_name, password);
    }

    /// <summary>
    /// Start a service by name.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="name">The name of the service.</param>
    /// <param name="args">Optional arguments to pass to the service.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The status code for the service.</returns>
    public static NtStatus StartService(string? machine_name, string name, string[] args, bool throw_on_error)
    {
        using var service = OpenService(machine_name, name, ServiceAccessRights.Start, throw_on_error);
        if (!service.IsSuccess)
            return service.Status;
        return service.Result.Start(args, throw_on_error);
    }

    /// <summary>
    /// Start a service by name.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="name">The name of the service.</param>
    /// <param name="args">Optional arguments to pass to the service.</param>
    public static void StartService(string? machine_name, string name, string[] args)
    {
        StartService(machine_name, name, args, true);
    }

    /// <summary>
    /// Start a service by name.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="args">Optional arguments to pass to the service.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The status code for the service.</returns>
    public static NtStatus StartService(string name, string[] args, bool throw_on_error)
    {
        return StartService(null, name, args, throw_on_error);
    }

    /// <summary>
    /// Start a service by name.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="args">Optional arguments to pass to the service.</param>
    /// <returns>The status code for the service.</returns>
    public static void StartService(string name, string[] args)
    {
        StartService(name, args, true);
    }

    /// <summary>
    /// Set a service's SID type.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="name">The name of the service.</param>
    /// <param name="sid_type">The SID type to set.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus SetServiceSidType(string? machine_name, string name, ServiceSidType sid_type, bool throw_on_error)
    {
        using var service = OpenService(machine_name, name, ServiceAccessRights.ChangeConfig, throw_on_error);
        if (!service.IsSuccess)
            return service.Status;
        return service.Result.SetServiceSidType(sid_type, throw_on_error);
    }

    /// <summary>
    /// Set a service's SID type.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="name">The name of the service.</param>
    /// <param name="sid_type">The SID type to set.</param>
    public static void SetServiceSidType(string? machine_name, string name, ServiceSidType sid_type)
    {
        SetServiceSidType(machine_name, name, sid_type, true);
    }

    /// <summary>
    /// Set a service's SID type.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="sid_type">The SID type to set.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus SetServiceSidType(string name, ServiceSidType sid_type, bool throw_on_error)
    {
        return SetServiceSidType(null, name, sid_type, throw_on_error);
    }

    /// <summary>
    /// Set a service's SID type.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="sid_type">The SID type to set.</param>
    public static void SetServiceSidType(string name, ServiceSidType sid_type)
    {
        SetServiceSidType(name, sid_type, true);
    }

    /// <summary>
    /// Set a service's delayed auto-start.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="name">The name of the service.</param>
    /// <param name="enabled">If true, the service is started after other auto-start services are started plus a short delay. Otherwise, the service is started during system boot.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus SetServiceDelayedAutoStart(string? machine_name, string name, bool enabled, bool throw_on_error)
    {
        using var service = OpenService(machine_name, name, ServiceAccessRights.ChangeConfig, throw_on_error);
        if (!service.IsSuccess)
            return service.Status;
        return service.Result.SetServiceDelayedAutoStart(enabled, throw_on_error);
    }

    /// <returns/>
    /// <inheritdoc cref="SetServiceDelayedAutoStart(string, string, bool, bool)"/>
    public static void SetServiceDelayedAutoStart(string? machine_name, string name, bool enabled)
    {
        SetServiceDelayedAutoStart(machine_name, name, enabled, true);
    }

    /// <returns/>
    /// <inheritdoc cref="SetServiceDelayedAutoStart(string, string, bool, bool)"/>
    public static void SetServiceDelayedAutoStart(string name, bool enabled, bool throw_on_error)
    {
        SetServiceDelayedAutoStart(null, name, enabled, throw_on_error);
    }


    /// <inheritdoc cref="SetServiceDelayedAutoStart(string, string, bool, bool)"/>
    public static void SetServiceDelayedAutoStart(string name, bool enabled)
    {
        SetServiceDelayedAutoStart(name, enabled, true);
    }

    /// <summary>
    /// Set a service's failure recover actions.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="name">The name of the service.</param>
    /// <param name="actions">Actions to be performed on service failure.
    /// <br/>If this value is null, <paramref name="reset_period"/> is ignored.
    /// <br/> If this value is empty, the reset period and array of failure actions are deleted.</param>
    /// <param name="reset_period">The time after which to reset the failure count to zero if there are no failures, in seconds. Specify -1 to indicate that this value should never be reset.</param>
    /// <param name="recover_command">The command line of the process for the CreateProcess function to execute in response to the command run service controller action.
    /// <br/> This process runs under the same account as the service.
    /// <br/> If this value is null, the command is unchanged.
    /// <br/> If the value is an empty string (""), the command is deleted and no program is run when the service fails.</param>
    /// <param name="reboot_msg">The message to be broadcast to server users before rebooting in response to the reboot action service controller action.
    /// <br/> If this value is null, the reboot message is unchanged.
    /// <br/> If the value is an empty string (""), the reboot message is deleted and no message is broadcast.
    /// <br/> This member can specify a localized string using the following format: <c>@[path]dllname,-strID</c>
    /// <br/> The string with identifier <c>strID</c> is loaded from <c>dllname</c>; <c>path</c> is optional.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus SetServiceFailureActions(string? machine_name, string name, IEnumerable<ServiceFailureAction> actions, int reset_period, string recover_command, string reboot_msg, bool throw_on_error)
    {
        using var service = OpenService(machine_name, name, ServiceAccessRights.ChangeConfig, throw_on_error);
        if (!service.IsSuccess)
            return service.Status;
        return service.Result.SetServiceFailureActions(actions, reset_period, recover_command, reboot_msg, throw_on_error);
    }

    /// <returns/>
    /// <inheritdoc cref="SetServiceFailureActions(string, string, IEnumerable{ServiceFailureAction}, int, string, string, bool)"/>
    public static void SetServiceFailureActions(string? machine_name, string name, IEnumerable<ServiceFailureAction> actions, int reset_period, string recover_command, string reboot_msg)
    {
        SetServiceFailureActions(machine_name, name, actions, reset_period, recover_command, reboot_msg, true);
    }

    /// <returns/>
    /// <inheritdoc cref="SetServiceFailureActions(string, string, IEnumerable{ServiceFailureAction}, int, string, string, bool)"/>
    public static void SetServiceFailureActions(string name, IEnumerable<ServiceFailureAction> actions, int reset_period, string recover_command, string reboot_msg, bool throw_on_error)
    {
        SetServiceFailureActions(null, name, actions, reset_period, recover_command, reboot_msg, throw_on_error);
    }

    /// <inheritdoc cref="SetServiceFailureActions(string, string, IEnumerable{ServiceFailureAction}, int, string, string, bool)"/>
    public static void SetServiceFailureActions(string name, IEnumerable<ServiceFailureAction> actions, int reset_period, string recover_command, string reboot_msg)
    {
        SetServiceFailureActions(name, actions, reset_period, recover_command, reboot_msg, true);
    }

    /// <summary>
    /// Set a service's required privileges.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="name">The name of the service.</param>
    /// <param name="privileges">The required privileges.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus SetServiceRequiredPrivileges(string? machine_name, string name, string[] privileges, bool throw_on_error)
    {
        using var service = OpenService(machine_name, name, ServiceAccessRights.ChangeConfig, throw_on_error);
        if (!service.IsSuccess)
            return service.Status;
        return service.Result.SetServiceRequiredPrivileges(privileges, throw_on_error);
    }

    /// <summary>
    /// Set a service's required privileges.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="name">The name of the service.</param>
    /// <param name="privileges">The required privileges.</param>
    public static void SetServiceRequiredPrivileges(string? machine_name, string name, string[] privileges)
    {
        SetServiceRequiredPrivileges(machine_name, name, privileges, true);
    }

    /// <summary>
    /// Set a service's required privileges.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="privileges">The required privileges.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus SetServiceRequiredPrivileges(string name, string[] privileges, bool throw_on_error)
    {
        return SetServiceRequiredPrivileges(null, name, privileges, throw_on_error);
    }

    /// <summary>
    /// Set a service's required privileges.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="privileges">The required privileges.</param>
    public static void SetServiceRequiredPrivileges(string name, string[] privileges)
    {
        SetServiceRequiredPrivileges(name, privileges, true);
    }

    /// <summary>
    /// Set a service's launch protected type.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="name">The name of the service.</param>
    /// <param name="protected_type">The protected type.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus SetServiceLaunchProtected(string? machine_name, string name, ServiceLaunchProtectedType protected_type, bool throw_on_error)
    {
        using var service = OpenService(machine_name, name, ServiceAccessRights.ChangeConfig, throw_on_error);
        if (!service.IsSuccess)
            return service.Status;
        return service.Result.SetServiceLaunchProtected(protected_type, throw_on_error);
    }

    /// <summary>
    /// Set a service's launch protected type.
    /// </summary>
    /// <param name="machine_name">The name of a target computer. Can be null or empty to specify local machine.</param>
    /// <param name="name">The name of the service.</param>
    /// <param name="protected_type">The protected type.</param>
    public static void SetServiceLaunchProtected(string? machine_name, string name, ServiceLaunchProtectedType protected_type)
    {
        SetServiceLaunchProtected(machine_name, name, protected_type, true);
    }

    /// <summary>
    /// Set a service's required privileges.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="protected_type">The protected type.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus SetServiceLaunchProtected(string name, ServiceLaunchProtectedType protected_type, bool throw_on_error)
    {
        return SetServiceLaunchProtected(null, name, protected_type, throw_on_error);
    }

    /// <summary>
    /// Set a service's SID type.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="protected_type">The protected type.</param>
    public static void SetServiceLaunchProtected(string name, ServiceLaunchProtectedType protected_type)
    {
        SetServiceLaunchProtected(name, protected_type, true);
    }
    #endregion
}
