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

using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32
{
#pragma warning disable 1591
    /// <summary>
    /// Service trigger type.
    /// </summary>
    public enum ServiceTriggerType
    {
        DeviceInterfaceArrival = 1,
        IPAddressAvailability = 2,
        DomainJoin = 3,
        FirewallPortEvent = 4,
        GroupPolicy = 5,
        NetworkEndpoint = 6,
        CustomSystemStateChange = 7,
        Custom = 20,
        Aggregate = 30,
    }

    public enum ServiceTriggerDataType
    {
        Binary = 1,
        String = 2,
        Level = 3,
        KeywordAny = 4,
        KeywordAll = 5,
    }

    public enum ServiceTriggerAction
    {
        Start = 1,
        Stop = 2
    }

    public enum ServiceStatus
    {
        Stopped = 1,
        StartPending = 2,
        StopPending = 3,
        Running = 4,
        ContinuePending = 5,
        PausePending = 6,
        Paused = 7,
    }

    [Flags]
    public enum ServiceControlManagerAccessRights : uint
    {
        CreateService = 0x0002,
        Connect = 0x0001,
        EnumerateService = 0x0004,
        Lock = 0x0008,
        ModifyBootConfig = 0x0020,
        QueryLockStatus = 0x0010,
        All = CreateService | Connect | EnumerateService
            | Lock | ModifyBootConfig | QueryLockStatus | ReadControl
            | Delete | WriteDac | WriteOwner,
        GenericRead = GenericAccessRights.GenericRead,
        GenericWrite = GenericAccessRights.GenericWrite,
        GenericExecute = GenericAccessRights.GenericExecute,
        GenericAll = GenericAccessRights.GenericAll,
        Delete = GenericAccessRights.Delete,
        ReadControl = GenericAccessRights.ReadControl,
        WriteDac = GenericAccessRights.WriteDac,
        WriteOwner = GenericAccessRights.WriteOwner,
        Synchronize = GenericAccessRights.Synchronize,
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
    }

    [Flags]
    public enum ServiceAccessRights : uint
    {
        ChangeConfig = 0x0002,
        EnumerateDependents = 0x0008,
        Interrogate = 0x0080,
        PauseContinue = 0x0040,
        QueryConfig = 0x0001,
        QueryStatus = 0x0004,
        Start = 0x0010,
        Stop = 0x0020,
        UserDefinedControl = 0x0100,
        SetStatus = 0x8000,
        All = ChangeConfig | EnumerateDependents | Interrogate | PauseContinue
            | QueryStatus | QueryConfig | Start | Stop | UserDefinedControl | ReadControl
            | Delete | WriteDac | WriteOwner,
        GenericRead = GenericAccessRights.GenericRead,
        GenericWrite = GenericAccessRights.GenericWrite,
        GenericExecute = GenericAccessRights.GenericExecute,
        GenericAll = GenericAccessRights.GenericAll,
        Delete = GenericAccessRights.Delete,
        ReadControl = GenericAccessRights.ReadControl,
        WriteDac = GenericAccessRights.WriteDac,
        WriteOwner = GenericAccessRights.WriteOwner,
        Synchronize = GenericAccessRights.Synchronize,
        MaximumAllowed = GenericAccessRights.MaximumAllowed,
        AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
    }

    internal class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeServiceHandle() : base(true)
        {
        }

        protected override bool ReleaseHandle()
        {
            return Win32NativeMethods.CloseServiceHandle(handle);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SERVICE_STATUS_PROCESS
    {
        public ServiceType dwServiceType;
        public ServiceStatus dwCurrentState;
        public int dwControlsAccepted;
        public int dwWin32ExitCode;
        public int dwServiceSpecificExitCode;
        public int dwCheckPoint;
        public int dwWaitHint;
        public int dwProcessId;
        public int dwServiceFlags;
    }

    internal enum SC_ENUM_TYPE {
        SC_ENUM_PROCESS_INFO = 0
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ENUM_SERVICE_STATUS_PROCESS
    {
        public IntPtr lpServiceName;
        public IntPtr lpDisplayName;
        public SERVICE_STATUS_PROCESS ServiceStatusProcess;
    }

    [Flags]
    public enum ServiceType
    {
        KernelDriver = 0x00000001,
        SystemDriver = 0x00000002,
        Win32OwnProcess = 0x00000010,
        Win32ShareProcess = 0x00000020,
        Win32 = Win32OwnProcess | Win32ShareProcess,
        UserService = 0x00000040,
        UserServiceInstance = 0x00000080,
        InteractiveProcess = 0x00000100
    }

    public enum ServiceState
    {
        All,
        Active,
        InActive
    }

    internal enum SC_STATUS_TYPE
    {
        SC_STATUS_PROCESS_INFO = 0
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SERVICE_TRIGGER_INFO
    {
        public int cTriggers;
        public IntPtr pTriggers;
        public IntPtr pReserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SERVICE_TRIGGER
    {
        public ServiceTriggerType dwTriggerType;
        public ServiceTriggerAction dwAction;
        public IntPtr pTriggerSubtype;
        public int cDataItems;
        public IntPtr pDataItems;

        public Guid GetSubType()
        {
            if (pTriggerSubtype != IntPtr.Zero)
            {
                return (Guid)Marshal.PtrToStructure(pTriggerSubtype, typeof(Guid));
            }
            return Guid.Empty;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SERVICE_TRIGGER_SPECIFIC_DATA_ITEM
    {
        public ServiceTriggerDataType dwDataType;
        public int cbData;
        public IntPtr pData;
    }

    public enum ServiceSidType
    {
        None = 0,
        Unrestricted = 1,
        Restricted = 3
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SERVICE_SID_INFO
    {
        public ServiceSidType dwServiceSidType;
    }

    public enum ServiceLaunchProtectedType
    {
        None = 0,
        Windows = 1,
        WindowsLight = 2,
        AntimalwareLight = 3,
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SERVICE_LAUNCH_PROTECTED_INFO
    {
        public ServiceLaunchProtectedType dwLaunchProtected;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct QUERY_SERVICE_CONFIG
    {
        public ServiceType dwServiceType;
        public int dwStartType;
        public int dwErrorControl;
        public IntPtr lpBinaryPathName;
        public IntPtr lpLoadOrderGroup;
        public int dwTagId;
        public IntPtr lpDependencies;
        public IntPtr lpServiceStartName;
        public IntPtr lpDisplayName;
    }

    #pragma warning restore
    /// <summary>
    /// Utilities for accessing services.
    /// </summary>
    public static class ServiceUtils
    {
        #region Private Members
        private const int SERVICE_CONFIG_TRIGGER_INFO = 8;
        private const int SERVICE_CONFIG_SERVICE_SID_INFO = 5;
        private const int SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO = 6;
        private const int SERVICE_CONFIG_LAUNCH_PROTECTED = 12;

        private static SecurityDescriptor GetServiceSecurityDescriptor(SafeServiceHandle handle, string type_name)
        {
            byte[] sd = new byte[8192];
            if (!Win32NativeMethods.QueryServiceObjectSecurity(handle, SecurityInformation.Dacl
                | SecurityInformation.Owner
                | SecurityInformation.Label
                | SecurityInformation.Group, sd, sd.Length, out int required))
            {
                throw new SafeWin32Exception();
            }

            return new SecurityDescriptor(sd, GetServiceNtType(type_name));
        }

        private static IEnumerable<ServiceTriggerInformation> GetTriggersForService(SafeServiceHandle service)
        {
            List<ServiceTriggerInformation> triggers = new List<ServiceTriggerInformation>();
            using (var buf = new SafeStructureInOutBuffer<SERVICE_TRIGGER_INFO>(8192, false))
            {
                if (!Win32NativeMethods.QueryServiceConfig2(service, SERVICE_CONFIG_TRIGGER_INFO,
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
                using (SafeHGlobalBuffer trigger_buffer = new SafeHGlobalBuffer(trigger_info.pTriggers,
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
        }

        private static IEnumerable<string> GetServiceRequiredPrivileges(SafeServiceHandle service)
        {
            using (var buf = new SafeHGlobalBuffer(8192))
            {
                if (!Win32NativeMethods.QueryServiceConfig2(service, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
                        buf, buf.Length, out int needed))
                {
                    return new string[0];
                }

                IntPtr str_pointer = buf.Read<IntPtr>(0);
                if (str_pointer == IntPtr.Zero)
                {
                    return new string[0];
                }

                SafeHGlobalBuffer str_buffer = new SafeHGlobalBuffer(str_pointer, 8192 - 8, false);
                ulong offset = 0;
                List<string> privs = new List<string>();
                while (offset < str_buffer.ByteLength)
                {
                    string s = str_buffer.ReadNulTerminatedUnicodeString(offset);
                    if (s.Length == 0)
                    {
                        break;
                    }
                    privs.Add(s);
                    offset += (ulong)(s.Length + 1) * 2;
                }
                return privs.AsReadOnly();
            }
        }

        private static ServiceSidType GetServiceSidType(SafeServiceHandle service)
        {
            using (var buf = new SafeStructureInOutBuffer<SERVICE_SID_INFO>())
            {
                if (!Win32NativeMethods.QueryServiceConfig2(service, SERVICE_CONFIG_SERVICE_SID_INFO,
                        buf, buf.Length, out int needed))
                {
                    return ServiceSidType.None;
                }
                return buf.Result.dwServiceSidType;
            }
        }

        private static ServiceLaunchProtectedType GetServiceLaunchProtectedType(SafeServiceHandle service)
        {
            using (var buf = new SafeStructureInOutBuffer<SERVICE_LAUNCH_PROTECTED_INFO>())
            {
                if (!Win32NativeMethods.QueryServiceConfig2(service, SERVICE_CONFIG_LAUNCH_PROTECTED,
                        buf, buf.Length, out int needed))
                {
                    return ServiceLaunchProtectedType.None;
                }
                return buf.Result.dwLaunchProtected;
            }
        }

        private static ServiceInformation GetServiceSecurityInformation(SafeServiceHandle scm, string name)
        {
            using (SafeServiceHandle service = Win32NativeMethods.OpenService(scm, name,
                ServiceAccessRights.QueryConfig | ServiceAccessRights.ReadControl))
            {
                if (service.IsInvalid)
                {
                    throw new SafeWin32Exception();
                }

                return new ServiceInformation(name, GetServiceSecurityDescriptor(service, "service"),
                    GetTriggersForService(service), GetServiceSidType(service),
                    GetServiceLaunchProtectedType(service), GetServiceRequiredPrivileges(service));
            }
        }

        private static string GetServiceDisplayName(SafeServiceHandle service)
        {
            using (var buf = new SafeStructureInOutBuffer<QUERY_SERVICE_CONFIG>(8192, false))
            {
                if (!Win32NativeMethods.QueryServiceConfig(service, buf, buf.Length, out int required))
                {
                    return string.Empty;
                }

                var result = buf.Result;
                if (result.lpDisplayName == IntPtr.Zero)
                {
                    return string.Empty;
                }

                return Marshal.PtrToStringUni(result.lpDisplayName);
            }
        }

        private static SERVICE_STATUS_PROCESS QueryStatus(SafeServiceHandle service)
        {
            using (var buffer = new SafeStructureInOutBuffer<SERVICE_STATUS_PROCESS>())
            {
                if (!Win32NativeMethods.QueryServiceStatusEx(service, SC_STATUS_TYPE.SC_STATUS_PROCESS_INFO,
                    buffer, buffer.Length, out int length))
                {
                    throw new SafeWin32Exception();
                }
                return buffer.Result;
            }
        }

        private static int GetServiceProcessId(SafeServiceHandle scm, string name)
        {
            using (SafeServiceHandle service = Win32NativeMethods.OpenService(scm, name, ServiceAccessRights.QueryStatus))
            {
                if (service.IsInvalid)
                {
                    throw new SafeWin32Exception();
                }

                return QueryStatus(service).dwProcessId;
            }
        }

        private static IEnumerable<RunningService> GetServices(SERVICE_STATE service_state, ServiceType service_types)
        {
            using (SafeServiceHandle scm = Win32NativeMethods.OpenSCManager(null, null,
                            ServiceControlManagerAccessRights.Connect | ServiceControlManagerAccessRights.EnumerateService))
            {
                if (scm.IsInvalid)
                {
                    throw new SafeWin32Exception();
                }

                const int Length = 32 * 1024;
                using (var buffer = new SafeHGlobalBuffer(Length))
                {
                    int resume_handle = 0;
                    while (true)
                    {
                        bool ret = Win32NativeMethods.EnumServicesStatusEx(scm, SC_ENUM_TYPE.SC_ENUM_PROCESS_INFO,
                            service_types, service_state, buffer,
                            buffer.Length, out int bytes_needed, out int services_returned, ref resume_handle, null);
                        Win32Error error = Win32Utils.GetLastWin32Error();
                        if (!ret && error != Win32Error.ERROR_MORE_DATA)
                        {
                            throw new SafeWin32Exception(error);
                        }

                        ENUM_SERVICE_STATUS_PROCESS[] services = new ENUM_SERVICE_STATUS_PROCESS[services_returned];
                        buffer.ReadArray(0, services, 0, services_returned);
                        foreach (var service in services)
                        {
                            yield return new RunningService(service);
                        }

                        if (ret)
                        {
                            break;
                        }
                    }
                }
            }
        }
        #endregion

        #region Static Methods
        /// <summary>
        /// Get the generic mapping for the SCM.
        /// </summary>
        /// <returns>The SCM generic mapping.</returns>
        public static GenericMapping GetScmGenericMapping()
        {
            GenericMapping mapping = new GenericMapping
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
            GenericMapping mapping = new GenericMapping
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
        /// <returns></returns>
        public static SecurityDescriptor GetScmSecurityDescriptor()
        {
            using (SafeServiceHandle scm = Win32NativeMethods.OpenSCManager(null, null,
                            ServiceControlManagerAccessRights.Connect | ServiceControlManagerAccessRights.ReadControl))
            {
                return GetServiceSecurityDescriptor(scm, "scm");
            }
        }

        /// <summary>
        /// Get the information about a service.
        /// </summary>
        /// <param name="name">The name of the service.</param>
        /// <returns>The servicec information.</returns>
        public static ServiceInformation GetServiceInformation(string name)
        {
            using (SafeServiceHandle scm = Win32NativeMethods.OpenSCManager(null, null,
                            ServiceControlManagerAccessRights.Connect | ServiceControlManagerAccessRights.ReadControl))
            {
                if (scm.IsInvalid)
                {
                    throw new SafeWin32Exception();
                }

                return GetServiceSecurityInformation(scm, name);
            }
        }

        /// <summary>
        /// Get the PID of a running service.
        /// </summary>
        /// <param name="name">The name of the service.</param>
        /// <returns>Returns the PID of the running service, or 0 if not running.</returns>
        /// <exception cref="SafeWin32Exception">Thrown on error.</exception>
        public static int GetServiceProcessId(string name)
        {
            using (SafeServiceHandle scm = Win32NativeMethods.OpenSCManager(null, null,
                            ServiceControlManagerAccessRights.Connect))
            {
                if (scm.IsInvalid)
                {
                    throw new SafeWin32Exception();
                }

                return GetServiceProcessId(scm, name);
            }
        }

        /// <summary>
        /// Get the PIDs of a list of running service.
        /// </summary>
        /// <param name="names">The names of the services.</param>
        /// <returns>Returns the PID of the running service, or 0 if not running.</returns>
        /// <exception cref="SafeWin32Exception">Thrown on error.</exception>
        public static IDictionary<string, int> GetServiceProcessIds(IEnumerable<string> names)
        {
            Dictionary<string, int> result = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            using (SafeServiceHandle scm = Win32NativeMethods.OpenSCManager(null, null,
                            ServiceControlManagerAccessRights.Connect))
            {
                if (scm.IsInvalid)
                {
                    throw new SafeWin32Exception();
                }

                foreach (var name in names)
                {
                    if (!result.ContainsKey(name))
                    {
                        result[name] = GetServiceProcessId(scm, name);
                    }
                }
            }
            return result;
        }

        /// <summary>
        /// Get a running service by name.
        /// </summary>
        /// <param name="name">The name of the service.</param>
        /// <returns>The running service.</returns>
        /// <remarks>This will return active and non-active services as well as drivers.</remarks>
        public static RunningService GetService(string name)
        {
            using (SafeServiceHandle scm = Win32NativeMethods.OpenSCManager(null, null,
                            ServiceControlManagerAccessRights.Connect))
            {
                if (scm.IsInvalid)
                {
                    throw new SafeWin32Exception();
                }

                using (var service = Win32NativeMethods.OpenService(scm, name, 
                    ServiceAccessRights.QueryConfig | ServiceAccessRights.QueryStatus))
                {
                    if (service.IsInvalid)
                    {
                        throw new SafeWin32Exception();
                    }
                    return new RunningService(name, GetServiceDisplayName(service), QueryStatus(service));
                }
            }
        }

        /// <summary>
        /// Get a list of all registered services.
        /// </summary>
        /// <param name="state">Specify state of services to get.</param>
        /// <param name="service_types">Specify the type filter for services.</param>
        /// <returns>A list of registered services.</returns>
        public static IEnumerable<RunningService> GetServices(ServiceState state, ServiceType service_types)
        {
            SERVICE_STATE state_flags;
            switch (state)
            {
                case ServiceState.All:
                    state_flags = SERVICE_STATE.SERVICE_STATE_ALL;
                    break;
                case ServiceState.Active:
                    state_flags = SERVICE_STATE.SERVICE_ACTIVE;
                    break;
                case ServiceState.InActive:
                    state_flags = SERVICE_STATE.SERVICE_INACTIVE;
                    break;
                default:
                    throw new ArgumentException("Invalid state.", nameof(state));
            }
            return GetServices(state_flags, service_types);
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
            return ServiceType.KernelDriver | ServiceType.SystemDriver;
        }

        /// <summary>
        /// Get a list of all registered services.
        /// </summary>
        /// <returns>A list of registered services.</returns>
        public static IEnumerable<RunningService> GetServices()
        {
            return GetServices(SERVICE_STATE.SERVICE_STATE_ALL, GetServiceTypes());
        }

        /// <summary>
        /// Get a list of all active running services with their process IDs.
        /// </summary>
        /// <returns>A list of all active running services with process IDs.</returns>
        public static IEnumerable<RunningService> GetRunningServicesWithProcessIds()
        {
            return GetServices(SERVICE_STATE.SERVICE_ACTIVE, GetServiceTypes());
        }

        /// <summary>
        /// Get a list of all drivers.
        /// </summary>
        /// <returns>A list of all drivers.</returns>
        public static IEnumerable<RunningService> GetDrivers()
        {
            return GetServices(SERVICE_STATE.SERVICE_STATE_ALL, GetDriverTypes());
        }

        /// <summary>
        /// Get a list of all active running drivers.
        /// </summary>
        /// <returns>A list of all active running drivers.</returns>
        public static IEnumerable<RunningService> GetRunningDrivers()
        {
            return GetServices(SERVICE_STATE.SERVICE_ACTIVE, GetDriverTypes());
        }

        /// <summary>
        /// Get a list of all services and drivers.
        /// </summary>
        /// <returns>A list of all services and drivers.</returns>
        public static IEnumerable<RunningService> GetServicesAndDrivers()
        {
            return GetServices(SERVICE_STATE.SERVICE_STATE_ALL, 
                GetDriverTypes() | GetServiceTypes());
        }

        /// <summary>
        /// Get a list of all services and drivers.
        /// </summary>
        /// <returns>A list of all services and drivers.</returns>
        public static IEnumerable<RunningService> GetRunningServicesAndDrivers()
        {
            return GetServices(SERVICE_STATE.SERVICE_ACTIVE,
                GetDriverTypes() | GetServiceTypes());
        }

        /// <summary>
        /// Get a fake NtType for a service.
        /// </summary>
        /// <param name="type_name">Service returns the service type, SCM returns SCM type.</param>
        /// <returns>The fake service NtType. Returns null if not a recognized type.</returns>
        public static NtType GetServiceNtType(string type_name)
        {
            switch (type_name.ToLower())
            {
                case "service":
                    return new NtType("Service", GetServiceGenericMapping(), 
                        typeof(ServiceAccessRights), typeof(ServiceAccessRights),
                        MandatoryLabelPolicy.NoWriteUp);
                case "scm":
                    return new NtType("SCM", GetScmGenericMapping(),
                        typeof(ServiceControlManagerAccessRights), typeof(ServiceControlManagerAccessRights),
                        MandatoryLabelPolicy.NoWriteUp);
            }
            return null;
        }
        #endregion
    }
}
