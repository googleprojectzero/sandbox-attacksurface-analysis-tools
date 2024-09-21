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

using NtCoreLib.Kernel.Interop;
using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Win32.Security.Interop;
using NtCoreLib.Win32.Service.Interop;
using NtCoreLib.Win32.Service.Triggers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;

namespace NtCoreLib.Win32.Service;

/// <summary>
/// Class to represent a handle to a service.
/// </summary>
public sealed class Service : ServiceBase<ServiceAccessRights>
{
    #region Private Members
    private IEnumerable<ServiceTriggerInformation> GetTriggersForService()
    {
        List<ServiceTriggerInformation> triggers = new();
        using var buf = new SafeStructureInOutBuffer<SERVICE_TRIGGER_INFO>(8192, false);
        if (!NativeMethods.QueryServiceConfig2(Handle, ServiceConfigInfoLevel.TriggerInfo,
            buf, buf.Length, out int required))
        {
            return triggers.AsReadOnly();
        }

        SERVICE_TRIGGER_INFO trigger_info = buf.Result;
        if (trigger_info.cTriggers == 0)
        {
            return triggers.AsReadOnly();
        }

        SERVICE_TRIGGER[] trigger_arr;
        using (SafeHGlobalBuffer trigger_buffer = new(trigger_info.pTriggers,
            trigger_info.cTriggers * Marshal.SizeOf(typeof(SERVICE_TRIGGER)), false))
        {
            trigger_arr = new SERVICE_TRIGGER[trigger_info.cTriggers];
            trigger_buffer.ReadArray(0, trigger_arr, 0, trigger_arr.Length);
        }

        for (int i = 0; i < trigger_arr.Length; ++i)
        {
            triggers.Add(ServiceTriggerInformation.GetTriggerInformation(trigger_arr[i]));
        }

        return triggers.AsReadOnly();
    }

    private IEnumerable<string> GetServiceRequiredPrivileges()
    {
        using var buf = new SafeHGlobalBuffer(8192);
        if (!NativeMethods.QueryServiceConfig2(Handle, ServiceConfigInfoLevel.RequiredPrivilegesInfo,
                buf, buf.Length, out int needed))
        {
            return new string[0];
        }

        return buf.Read<IntPtr>(0).GetMultiString();
    }

    private ServiceSidType GetServiceSidType()
    {
        using var buf = new SafeStructureInOutBuffer<SERVICE_SID_INFO>();
        if (!NativeMethods.QueryServiceConfig2(Handle, ServiceConfigInfoLevel.ServiceSidInfo,
                buf, buf.Length, out int needed))
        {
            return ServiceSidType.None;
        }
        return buf.Result.dwServiceSidType;
    }

    private ServiceLaunchProtectedType GetServiceLaunchProtectedType()
    {
        using var buf = new SafeStructureInOutBuffer<SERVICE_LAUNCH_PROTECTED_INFO>();
        if (!NativeMethods.QueryServiceConfig2(Handle, ServiceConfigInfoLevel.LaunchProtected,
                buf, buf.Length, out int needed))
        {
            return ServiceLaunchProtectedType.None;
        }
        return buf.Result.dwLaunchProtected;
    }

    private bool GetDelayedStart()
    {
        using var buf = new SafeStructureInOutBuffer<SERVICE_DELAYED_AUTO_START_INFO>();
        if (!NativeMethods.QueryServiceConfig2(Handle, ServiceConfigInfoLevel.DelayedAutoStartInfo,
                buf, buf.Length, out int needed))
        {
            return false;
        }
        return buf.Result.fDelayedAutostart;
    }

    //private NtResult<SafeStructureInOutBuffer<QUERY_SERVICE_CONFIG>> QueryConfig(bool throw_on_error)
    //{
    //    using var buf = new SafeStructureInOutBuffer<QUERY_SERVICE_CONFIG>(8192, false);
    //    return NativeMethods.QueryServiceConfig(Handle, buf, buf.Length,
    //        out int required).CreateWin32Result(throw_on_error, () => buf.Detach());
    //}
    #endregion

    #region Internal Members
    internal Service(SafeServiceHandle handle, string name, string? machine_name, ServiceAccessRights granted_access) 
        : base(handle, name, machine_name, granted_access, ServiceUtils.SERVICE_NT_TYPE_NAME)
    {
    }
    #endregion

    #region Public Properties
    /// <summary>
    /// The name of the service.
    /// </summary>
    public string Name => _name;

    /// <summary>
    /// Get the service information.
    /// </summary>
    public ServiceConfig Config => QueryConfig(true).Result;

    /// <summary>
    /// Get the service status.
    /// </summary>
    public ServiceStatusProcess Status => QueryStatus(true).Result;

    /// <summary>
    /// Get the service display name.
    /// </summary>
    public string DisplayName => QueryDisplayName(true).Result;
    #endregion

    #region Public Methods
    /// <summary>
    /// Query the service configuration.
    /// </summary>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The service configuration.</returns>
    public NtResult<ServiceConfig> QueryConfig(bool throw_on_error)
    {
        using var buf = new SafeStructureInOutBuffer<QUERY_SERVICE_CONFIG>(8192, false);
        if (!NativeMethods.QueryServiceConfig(Handle, buf, buf.Length, out int bytes_needed))
            return Win32Utils.CreateResultFromDosError<ServiceConfig>(throw_on_error);

        return new ServiceConfig(_machine_name, Name,
            GetTriggersForService(), GetServiceSidType(),
            GetServiceLaunchProtectedType(), GetServiceRequiredPrivileges(),
            buf, GetDelayedStart()).CreateResult();
    }

    /// <summary>
    /// Query the service status.
    /// </summary>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The service status.</returns>
    public NtResult<ServiceStatusProcess> QueryStatus(bool throw_on_error)
    {
        using var buffer = new SafeStructureInOutBuffer<SERVICE_STATUS_PROCESS>();
        return NativeMethods.QueryServiceStatusEx(Handle, SC_STATUS_TYPE.SC_STATUS_PROCESS_INFO,
            buffer, buffer.Length, out int length)
            .CreateWin32Result(throw_on_error, () => new ServiceStatusProcess(buffer.Result));
    }

    /// <summary>
    /// Query the service display name.
    /// </summary>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The service display name.</returns>
    public NtResult<string> QueryDisplayName(bool throw_on_error)
    {
        using var config = QueryConfig(throw_on_error);
        if (!config.IsSuccess)
            return config.Cast<string>();
        return config.Result.DisplayName.CreateResult();
    }

    /// <summary>
    /// Start the service.
    /// </summary>
    /// <param name="args">Optional arguments.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public NtStatus Start(string[]? args, bool throw_on_error)
    {
        return NativeMethods.StartService(Handle,
                args?.Length ?? 0, args).ToNtException(throw_on_error);
    }

    /// <summary>
    /// Start the service.
    /// </summary>
    /// <param name="args">Optional arguments.</param>
    public void Start(string[]? args)
    {
        Start(args, true);
    }

    /// <summary>
    /// Delete the service.
    /// </summary>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status.</returns>
    public NtStatus Delete(bool throw_on_error)
    {
        return NativeMethods.DeleteService(Handle).ToNtException(throw_on_error);
    }

    /// <summary>
    /// Delete the service.
    /// </summary>
    public void Delete()
    {
        Delete(true);
    }

    /// <summary>
    /// Send a control code to the service.
    /// </summary>
    /// <param name="control_code">The control code to send. If >= 128 will be sent as a custom control code.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The service status.</returns>
    public NtResult<ServiceStatusProcess> Control(ServiceControlCode control_code, bool throw_on_error)
    {
        return NativeMethods.ControlService(Handle, control_code, 
            out SERVICE_STATUS status).CreateWin32Result(throw_on_error, () => new ServiceStatusProcess(status));
    }

    /// <summary>
    /// Send a control code to the service.
    /// </summary>
    /// <param name="control_code">The control code to send. If >= 128 will be sent as a custom control code.</param>
    /// <returns>The service status.</returns>
    public ServiceStatusProcess Control(ServiceControlCode control_code)
    {
        return Control(control_code, true).Result;
    }

    /// <summary>
    /// Change service configuration.
    /// </summary>
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
    public NtStatus ChangeServiceConfig(
        string? display_name,
        ServiceType? service_type,
        ServiceStartType? start_type,
        ServiceErrorControl? error_control,
        string? binary_path_name,
        int? tag_id,
        string? load_order_group,
        IEnumerable<string>? dependencies,
        string? service_start_name,
        SecureString? password,
        bool throw_on_error)
    {
        using var pwd = new SecureStringMarshalBuffer(password);
        return NativeMethods.ChangeServiceConfig(Handle,
            service_type ?? (ServiceType)(-1), start_type ?? (ServiceStartType)(-1),
            error_control ?? (ServiceErrorControl)(-1), binary_path_name, load_order_group,
            tag_id.HasValue ? new OptionalInt32(tag_id.Value) : null, dependencies.ToMultiString(),
            service_start_name, pwd, display_name).ToNtException(throw_on_error);
    }

    /// <summary>
    /// Set a service's SID type.
    /// </summary>
    /// <param name="sid_type">The SID type to set.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public NtStatus SetServiceSidType(ServiceSidType sid_type, bool throw_on_error)
    {
        return ChangeConfig2(ServiceConfigInfoLevel.ServiceSidInfo,
            new SERVICE_SID_INFO() { dwServiceSidType = sid_type }, throw_on_error);
    }

    /// <summary>
    /// Set a service's SID type.
    /// </summary>
    /// <param name="sid_type">The SID type to set.</param>
    public void SetServiceSidType(ServiceSidType sid_type)
    {
        SetServiceSidType(sid_type, true);
    }

    /// <summary>
    /// Set a service's delayed auto-start.
    /// </summary>
    /// <param name="enabled">If true, the service is started after other auto-start services are started plus a short delay. Otherwise, the service is started during system boot.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public NtStatus SetServiceDelayedAutoStart(bool enabled, bool throw_on_error)
    {
        return ChangeConfig2(ServiceConfigInfoLevel.DelayedAutoStartInfo,
            new SERVICE_DELAYED_AUTO_START_INFO() { fDelayedAutostart = enabled }, throw_on_error);
    }

    /// <summary>
    /// Set a service's delayed auto-start.
    /// </summary>
    /// <param name="enabled">If true, the service is started after other auto-start services are started plus a short delay. Otherwise, the service is started during system boot.</param>
    public void SetServiceDelayedAutoStart(bool enabled)
    {
        SetServiceDelayedAutoStart(enabled, true);
    }

    /// <summary>
    /// Set a service's failure recover actions.
    /// </summary>
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
    public NtStatus SetServiceFailureActions(IEnumerable<ServiceFailureAction>? actions, int reset_period, string? recover_command, string? reboot_msg, bool throw_on_error)
    {
        var actions_array = actions?.ToArray();

        using var actions_buffer = actions_array?.ToBuffer() ?? SafeHGlobalBuffer.Null;
        var fa_struct = new SERVICE_FAILURE_ACTIONS
        {
            dwResetPeriod = reset_period,
            lpRebootMsg = reboot_msg,
            lpCommand = recover_command,
            cActions = actions_array?.Length ?? 0,
            lpsaActions = actions_buffer,
        };

        return ChangeConfig2(ServiceConfigInfoLevel.FailureActions, fa_struct, throw_on_error);
    }

    /// <summary>
    /// Set a service's failure recover actions.
    /// </summary>
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
    public void SetServiceFailureActions(IEnumerable<ServiceFailureAction>? actions, int reset_period, string? recover_command, string? reboot_msg)
    {
        SetServiceFailureActions(actions, reset_period, recover_command, reboot_msg, true);
    }

    /// <summary>
    /// Set a service's required privileges.
    /// </summary>
    /// <param name="privileges">The required privileges.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public NtStatus SetServiceRequiredPrivileges(string[]? privileges, bool throw_on_error)
    {
        return ChangeConfig2(ServiceConfigInfoLevel.RequiredPrivilegesInfo,
            new SERVICE_REQUIRED_PRIVILEGES_INFO() { pmszRequiredPrivileges = privileges.ToMultiString() ?? "\0" }, throw_on_error);
    }

    /// <summary>
    /// Set a service's required privileges.
    /// </summary>
    /// <param name="privileges">The required privileges.</param>
    public void SetServiceRequiredPrivileges(string[]? privileges)
    {
        SetServiceRequiredPrivileges(privileges, true);
    }

    /// <summary>
    /// Set a service's launch protected type.
    /// </summary>
    /// <param name="protected_type">The protected type.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public NtStatus SetServiceLaunchProtected(ServiceLaunchProtectedType protected_type, bool throw_on_error)
    {
        return ChangeConfig2(ServiceConfigInfoLevel.LaunchProtected,
            new SERVICE_LAUNCH_PROTECTED_INFO() { dwLaunchProtected = protected_type }, throw_on_error);
    }

    /// <summary>
    /// Set a service's launch protected type.
    /// </summary>
    /// <param name="protected_type">The protected type.</param>
    public void SetServiceLaunchProtected(ServiceLaunchProtectedType protected_type)
    {
        SetServiceLaunchProtected(protected_type, true);
    }

    /// <summary>
    /// Query the service configuration value.
    /// </summary>
    /// <param name="info_level">The type of configuration to query.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The buffer containing the configuration data.</returns>
    public NtResult<SafeBufferGeneric> QueryConfig2(ServiceConfigInfoLevel info_level, bool throw_on_error)
    {
        if (!NativeMethods.QueryServiceConfig2(Handle, info_level, SafeHGlobalBuffer.Null, 0, out int bytes_needed))
        {
            Win32Error error = Win32Utils.GetLastWin32Error();
            if (error != Win32Error.ERROR_INSUFFICIENT_BUFFER)
            {
                return error.CreateResultFromDosError<SafeBufferGeneric>(throw_on_error);
            }
        }

        using var buffer = new SafeHGlobalBuffer(bytes_needed);
        return NativeMethods.QueryServiceConfig2(Handle, info_level, buffer, buffer.Length,
            out bytes_needed).CreateWin32Result<SafeBufferGeneric>(throw_on_error, () => buffer.Detach());
    }

    /// <summary>
    /// Query the service configuration value.
    /// </summary>
    /// <param name="info_level">The type of configuration to query.</param>
    /// <returns>The buffer containing the configuration data.</returns>
    public SafeBufferGeneric QueryConfig2(ServiceConfigInfoLevel info_level)
    {
        return QueryConfig2(info_level, true).Result;
    }

    /// <summary>
    /// Query the fixed size service configuration value.
    /// </summary>
    /// <param name="info_level">The type of configuration to query.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The buffer containing the configuration data.</returns>
    public NtResult<T> QueryConfig2<T>(ServiceConfigInfoLevel info_level, bool throw_on_error) where T : new()
    {
        using var buffer = new SafeStructureInOutBuffer<T>();
        return NativeMethods.QueryServiceConfig2(Handle, info_level, buffer, buffer.Length,
            out int bytes_needed).CreateWin32Result(throw_on_error, () => buffer.Result);
    }

    /// <summary>
    /// Change a service configuration value.
    /// </summary>
    /// <param name="info_level">The type of configuration to change.</param>
    /// <param name="buffer">The buffer containing the data to change</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public NtStatus ChangeConfig2(ServiceConfigInfoLevel info_level, SafeBuffer buffer, bool throw_on_error)
    {
        return NativeMethods.ChangeServiceConfig2(Handle, info_level, buffer).ToNtException(throw_on_error);
    }

    /// <summary>
    /// Change a service configuration value.
    /// </summary>
    /// <param name="info_level">The type of configuration to change.</param>
    /// <param name="buffer">The buffer containing the data to change</param>
    public void ChangeConfig2(ServiceConfigInfoLevel info_level, SafeBuffer buffer)
    {
        ChangeConfig2(info_level, buffer, true);
    }

    /// <summary>
    /// Change a service configuration value.
    /// </summary>
    /// <param name="info_level">The type of configuration to change.</param>
    /// <param name="value">The value containing the data to change</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <typeparam name="T">The type of structure to set.</typeparam>
    /// <returns>The NT status code.</returns>
    public NtStatus ChangeConfig2<T>(ServiceConfigInfoLevel info_level, T value, bool throw_on_error) where T : struct
    {
        using var buffer = value.ToBuffer();
        return ChangeConfig2(info_level, buffer, throw_on_error);
    }

    /// <summary>
    /// Change a service configuration value.
    /// </summary>
    /// <param name="info_level">The type of configuration to change.</param>
    /// <param name="value">The value containing the data to change</param>
    /// <typeparam name="T">The type of structure to set.</typeparam>
    public void ChangeConfig2<T>(ServiceConfigInfoLevel info_level, T value) where T : struct
    {
        ChangeConfig2(info_level, value, true);
    }
    #endregion

    #region Static Methods
    /// <summary>
    /// Open a service object.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="desired_access">The desired access for the service.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The opened service object.</returns>
    public static NtResult<Service> Open(string name, ServiceAccessRights desired_access, bool throw_on_error)
    {
        using var scm = ServiceControlManager.Open(null, null, ServiceControlManagerAccessRights.Connect, throw_on_error);
        if (!scm.IsSuccess)
            return scm.Cast<Service>();
        return scm.Result.OpenService(name, desired_access, throw_on_error);
    }

    /// <summary>
    /// Open a service object.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="desired_access">The desired access for the service.</param>
    /// <returns>The opened service object.</returns>
    public static Service Open(string name, ServiceAccessRights desired_access)
    {
        return Open(name, desired_access, true).Result;
    }

    /// <summary>
    /// Open a service object.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <returns>The opened service object.</returns>
    public static Service Open(string name)
    {
        return Open(name, ServiceAccessRights.MaximumAllowed);
    }
    #endregion
}
