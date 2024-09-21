//  Copyright 2021 Google Inc. All Rights Reserved.
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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Win32.Security.Interop;
using NtCoreLib.Win32.Service.Interop;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;

namespace NtCoreLib.Win32.Service;

/// <summary>
/// Class to represent a handle to the SCM.
/// </summary>
public sealed class ServiceControlManager : ServiceBase<ServiceControlManagerAccessRights>
{
    #region Private Members
    private ServiceControlManager(SafeServiceHandle handle, string? machine_name, ServiceControlManagerAccessRights granted_access) 
        : base(handle, "SCM", machine_name, granted_access, ServiceUtils.SCM_NT_TYPE_NAME)
    {
    }
    #endregion

    #region Public Constants
    /// <summary>
    /// Active services database.
    /// </summary>
    public const string SERVICES_ACTIVE_DATABASE = "ServicesActive";

    /// <summary>
    /// Failed services database.
    /// </summary>
    public const string SERVICES_FAILED_DATABASE = "ServicesFailed";
    #endregion

    #region Static Methods
    /// <summary>
    /// Open an instance of the SCM.
    /// </summary>
    /// <param name="machine_name">The machine name for the SCM.</param>
    /// <param name="database_name">The database name. Specify SERVICES_ACTIVE_DATABASE or SERVICES_FAILED_DATABASE. 
    /// If null then SERVICES_ACTIVE_DATABASE is used.</param>
    /// <param name="desired_access">The desired access for the SCM connection.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The SCM instance.</returns>
    public static NtResult<ServiceControlManager> Open(string? machine_name, string? database_name, 
        ServiceControlManagerAccessRights desired_access, bool throw_on_error)
    {
        if (machine_name == string.Empty)
            machine_name = null;
        if (database_name == string.Empty)
            database_name = null;
        return NativeMethods.OpenSCManager(machine_name, database_name, 
            desired_access).CreateWin32Result(throw_on_error, 
            h => new ServiceControlManager(h, machine_name, desired_access));
    }

    /// <summary>
    /// Open an instance of the SCM.
    /// </summary>
    /// <param name="machine_name">The machine name for the SCM.</param>
    /// <param name="database_name">The database name. Specify SERVICES_ACTIVE_DATABASE or SERVICES_FAILED_DATABASE. 
    /// If null then SERVICES_ACTIVE_DATABASE is used.</param>
    /// <param name="desired_access">The desired access for the SCM connection.</param>
    /// <returns>The SCM instance.</returns>
    public static ServiceControlManager Open(string? machine_name, string? database_name,
        ServiceControlManagerAccessRights desired_access)
    {
        return Open(machine_name, database_name, desired_access, true).Result;
    }

    /// <summary>
    /// Open an instance of the SCM.
    /// </summary>
    /// <param name="machine_name">The machine name for the SCM.</param>
    /// <param name="desired_access">The desired access for the SCM connection.</param>
    /// <returns>The SCM instance.</returns>
    public static ServiceControlManager Open(string? machine_name, 
        ServiceControlManagerAccessRights desired_access)
    {
        return Open(machine_name, null, desired_access);
    }

    /// <summary>
    /// Open an instance of the SCM on the local machine.
    /// </summary>
    /// <param name="desired_access">The desired access for the SCM connection.</param>
    /// <returns>The SCM instance.</returns>
    public static ServiceControlManager Open(ServiceControlManagerAccessRights desired_access = ServiceControlManagerAccessRights.MaximumAllowed)
    {
        return Open(null, desired_access);
    }
    #endregion

    #region Public Methods
    /// <summary>
    /// Get the Win32 services for the SCM.
    /// </summary>
    /// <param name="service_state">The state of the services to return.</param>
    /// <param name="service_types">The types of services to return.</param>
    /// <param name="throw_on_error">True throw on error.</param>
    /// <returns>The list of services status.</returns>
    /// <remarks>SCM must have been opened with EnumerateService access.</remarks>
    public NtResult<IEnumerable<EnumServiceStatusProcess>> EnumerateServiceStatus(ServiceState service_state, ServiceType service_types, bool throw_on_error)
    {
        var state = service_state switch
        {
            ServiceState.All => SERVICE_STATE.SERVICE_STATE_ALL,
            ServiceState.Active => SERVICE_STATE.SERVICE_ACTIVE,
            ServiceState.InActive => SERVICE_STATE.SERVICE_INACTIVE,
            _ => throw new ArgumentException("Invalid service state", nameof(service_state)),
        };
        List<EnumServiceStatusProcess> ret_services = new();
        const int Length = 32 * 1024;
        using var buffer = new SafeHGlobalBuffer(Length);
        int resume_handle = 0;
        while (true)
        {
            bool ret = NativeMethods.EnumServicesStatusEx(Handle, SC_ENUM_TYPE.SC_ENUM_PROCESS_INFO,
                service_types, state, buffer, buffer.Length, out int bytes_needed, out int services_returned,
                ref resume_handle, null);
            Win32Error error = Win32Utils.GetLastWin32Error();
            if (!ret && error != Win32Error.ERROR_MORE_DATA)
            {
                return error.CreateResultFromDosError<IEnumerable<EnumServiceStatusProcess>>(throw_on_error);
            }

            ENUM_SERVICE_STATUS_PROCESS[] services = new ENUM_SERVICE_STATUS_PROCESS[services_returned];
            buffer.ReadArray(0, services, 0, services_returned);
            ret_services.AddRange(services.Select(s => new EnumServiceStatusProcess(s)));
            if (ret)
            {
                break;
            }
        }
        return ret_services.CreateResult().Cast<IEnumerable<EnumServiceStatusProcess>>();
    }

    /// <summary>
    /// Get the Win32 services for the SCM.
    /// </summary>
    /// <param name="service_state">The state of the services to return.</param>
    /// <param name="service_types">The types of services to return.</param>
    /// <returns>The list of services.</returns>
    /// <remarks>SCM must have been opened with EnumerateService access.</remarks>
    public IEnumerable<EnumServiceStatusProcess> EnumerateServiceStatus(ServiceState service_state, ServiceType service_types)
    {
        return EnumerateServiceStatus(service_state, service_types, true).Result;
    }

    /// <summary>
    /// Open a service object.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="desired_access">The desired access for the service.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The opened service object.</returns>
    public NtResult<Service> OpenService(string name, ServiceAccessRights desired_access, bool throw_on_error)
    {
        return NativeMethods.OpenService(Handle, name, 
            desired_access).CreateWin32Result(throw_on_error, h => new Service(h, name, _machine_name, desired_access));
    }

    /// <summary>
    /// Open a service object.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="desired_access">The desired access for the service.</param>
    /// <returns>The opened service object.</returns>
    public Service OpenService(string name, ServiceAccessRights desired_access)
    {
        return OpenService(name, desired_access, true).Result;
    }

    /// <summary>
    /// Open a service object.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <returns>The opened service object.</returns>
    public Service OpenService(string name)
    {
        return OpenService(name, ServiceAccessRights.MaximumAllowed);
    }

    /// <summary>
    /// Create a new service.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="display_name">The display name for the service.</param>
    /// <param name="desired_access">Desired access for the service handle.</param>
    /// <param name="service_type">The service type.</param>
    /// <param name="start_type">The service start type.</param>
    /// <param name="error_control">Error control.</param>
    /// <param name="binary_path_name">Path to the service executable.</param>
    /// <param name="load_order_group">Load group order.</param>
    /// <param name="dependencies">List of service dependencies.</param>
    /// <param name="service_start_name">The username for the service.</param>
    /// <param name="password">Password for the username if needed.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The handle to the service.</returns>
    public NtResult<Service> CreateService(
        string name,
        string display_name,
        ServiceAccessRights desired_access,
        ServiceType service_type,
        ServiceStartType start_type,
        ServiceErrorControl error_control,
        string binary_path_name,
        string? load_order_group,
        IEnumerable<string>? dependencies,
        string? service_start_name,
        SecureString? password,
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

        using var pwd = new SecureStringMarshalBuffer(password);
        return NativeMethods.CreateService(Handle, name, display_name, desired_access,
                service_type, start_type, error_control, binary_path_name, load_order_group, null, dependencies.ToMultiString(),
                string.IsNullOrEmpty(service_start_name) ? null : service_start_name, pwd)
            .CreateWin32Result(throw_on_error, h => new Service(h, name, _machine_name, desired_access));
    }
    #endregion
}
