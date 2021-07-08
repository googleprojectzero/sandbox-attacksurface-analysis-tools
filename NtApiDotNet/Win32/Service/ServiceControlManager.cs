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

using NtApiDotNet.Security;
using NtApiDotNet.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Service
{
    /// <summary>
    /// Class to represent a handle to the SCM.
    /// </summary>
    public sealed class ServiceControlManager : IDisposable, INtObjectSecurity
    {
        #region Private Members
        private readonly SafeServiceHandle _handle;
        private readonly string _machine_name;
        private readonly ServiceControlManagerAccessRights _granted_access;

        private ServiceControlManager(SafeServiceHandle handle, string machine_name, ServiceControlManagerAccessRights granted_access)
        {
            _handle = handle;
            _machine_name = machine_name;
            _granted_access = granted_access;
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
        public static NtResult<ServiceControlManager> Open(string machine_name, string database_name, 
            ServiceControlManagerAccessRights desired_access, bool throw_on_error)
        {
            if (machine_name == string.Empty)
                machine_name = null;
            if (database_name == string.Empty)
                database_name = null;
            SafeServiceHandle scm = Win32NativeMethods.OpenSCManager(machine_name, database_name, desired_access);
            if (!scm.IsInvalid)
                return new ServiceControlManager(scm, machine_name, desired_access).CreateResult();
            return Win32Utils.CreateResultFromDosError<ServiceControlManager>(throw_on_error);
        }

        /// <summary>
        /// Open an instance of the SCM.
        /// </summary>
        /// <param name="machine_name">The machine name for the SCM.</param>
        /// <param name="database_name">The database name. Specify SERVICES_ACTIVE_DATABASE or SERVICES_FAILED_DATABASE. 
        /// If null then SERVICES_ACTIVE_DATABASE is used.</param>
        /// <param name="desired_access">The desired access for the SCM connection.</param>
        /// <returns>The SCM instance.</returns>
        public static ServiceControlManager Open(string machine_name, string database_name,
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
        public static ServiceControlManager Open(string machine_name, 
            ServiceControlManagerAccessRights desired_access)
        {
            return Open(machine_name, null, desired_access);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Get the Win32 services for the SCM.
        /// </summary>
        /// <param name="service_state">The state of the services to return.</param>
        /// <param name="service_types">The types of services to return.</param>
        /// <param name="throw_on_error">True throw on error.</param>
        /// <returns>The list of services.</returns>
        /// <remarks>SCM must have been opened with EnumerateService access.</remarks>
        public NtResult<IEnumerable<Win32Service>> GetServices(ServiceState service_state, ServiceType service_types, bool throw_on_error)
        {
            SERVICE_STATE state;
            switch (service_state)
            {
                case ServiceState.All:
                    state = SERVICE_STATE.SERVICE_STATE_ALL;
                    break;
                case ServiceState.Active:
                    state = SERVICE_STATE.SERVICE_ACTIVE;
                    break;
                case ServiceState.InActive:
                    state = SERVICE_STATE.SERVICE_INACTIVE;
                    break;
                default:
                    throw new ArgumentException("Invalid service state", nameof(service_state));
            }

            List<Win32Service> ret_services = new List<Win32Service>();
            const int Length = 32 * 1024;
            using (var buffer = new SafeHGlobalBuffer(Length))
            {
                int resume_handle = 0;
                while (true)
                {
                    bool ret = Win32NativeMethods.EnumServicesStatusEx(_handle, SC_ENUM_TYPE.SC_ENUM_PROCESS_INFO,
                        service_types, state, buffer, buffer.Length, out int bytes_needed, out int services_returned, 
                        ref resume_handle, null);
                    Win32Error error = Win32Utils.GetLastWin32Error();
                    if (!ret && error != Win32Error.ERROR_MORE_DATA)
                    {
                        return error.CreateResultFromDosError<IEnumerable<Win32Service>>(throw_on_error);
                    }

                    ENUM_SERVICE_STATUS_PROCESS[] services = new ENUM_SERVICE_STATUS_PROCESS[services_returned];
                    buffer.ReadArray(0, services, 0, services_returned);
                    ret_services.AddRange(services.Select(s => new Win32Service(_machine_name, s)));
                    if (ret)
                    {
                        break;
                    }
                }
            }
            return ret_services.CreateResult().Cast<IEnumerable<Win32Service>>();
        }

        /// <summary>
        /// Get the Win32 services for the SCM.
        /// </summary>
        /// <param name="service_state">The state of the services to return.</param>
        /// <param name="service_types">The types of services to return.</param>
        /// <returns>The list of services.</returns>
        /// <remarks>SCM must have been opened with EnumerateService access.</remarks>
        public IEnumerable<Win32Service> GetServices(ServiceState service_state, ServiceType service_types)
        {
            return GetServices(service_state, service_types, true).Result;
        }

        /// <summary>
        /// Dispose the object.
        /// </summary>
        public void Dispose()
        {
            _handle.Close();
        }
        #endregion

        #region Internal Members
        internal SafeServiceHandle Handle => _handle;
        #endregion

        #region INtObjectSecurity Implementation
        NtType INtObjectSecurity.NtType => NtType.GetTypeByName(ServiceUtils.SCM_NT_TYPE_NAME);

        string INtObjectSecurity.ObjectName => string.IsNullOrEmpty(_machine_name) ? "SCM" : $@"SCM (\\{_machine_name})";

        bool INtObjectSecurity.IsContainer => false;

        SecurityDescriptor INtObjectSecurity.SecurityDescriptor => GetSecurityDescriptor(SafeServiceHandle.DEFAULT_SECURITY_INFORMATION);

        bool INtObjectSecurity.IsAccessMaskGranted(AccessMask access)
        {
            // We can't tell if we really have access or not, so just assume we do.
            if (_granted_access.HasFlagSet(ServiceControlManagerAccessRights.MaximumAllowed))
                return true;
            return _granted_access.HasFlagAllSet(access.ToSpecificAccess<ServiceControlManagerAccessRights>());
        }

        /// <summary>
        /// Get the security descriptor specifying which parts to retrieve
        /// </summary>
        /// <param name="security_information">What parts of the security descriptor to retrieve</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The security descriptor</returns>
        public NtResult<SecurityDescriptor> GetSecurityDescriptor(SecurityInformation security_information, bool throw_on_error)
        {
            return _handle.GetSecurityDescriptor(ServiceUtils.SCM_NT_TYPE_NAME, security_information, throw_on_error);
        }

        /// <summary>
        /// Get the security descriptor specifying which parts to retrieve
        /// </summary>
        /// <param name="security_information">What parts of the security descriptor to retrieve</param>
        /// <returns>The security descriptor</returns>
        public SecurityDescriptor GetSecurityDescriptor(SecurityInformation security_information)
        {
            return GetSecurityDescriptor(security_information, true).Result;
        }

        /// <summary>
        /// Set the object's security descriptor
        /// </summary>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="security_information">What parts of the security descriptor to set</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        public NtStatus SetSecurityDescriptor(SecurityDescriptor security_descriptor, SecurityInformation security_information, bool throw_on_error)
        {
            return _handle.SetSecurityDescriptor(security_information, security_descriptor, throw_on_error);
        }

        /// <summary>
        /// Set the object's security descriptor
        /// </summary>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="security_information">What parts of the security descriptor to set</param>
        public void SetSecurityDescriptor(SecurityDescriptor security_descriptor, SecurityInformation security_information)
        {
            SetSecurityDescriptor(security_descriptor, security_information, true);
        }

        #endregion
    }
}
