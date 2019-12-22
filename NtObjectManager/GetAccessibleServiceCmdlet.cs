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

using NtApiDotNet;
using NtApiDotNet.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.ServiceProcess;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="description">Check mode for accessible services.</para>
    /// </summary>
    public enum ServiceCheckMode
    {
        /// <summary>
        /// Only services.
        /// </summary>
        ServiceOnly,
        /// <summary>
        /// Only drivers.
        /// </summary>
        DriverOnly,
        /// <summary>
        /// Services and drivers.
        /// </summary>
        ServiceAndDriver
    }

    /// <summary>
    /// <para type="description">Access check result for a service.</para>
    /// </summary>
    public class ServiceAccessCheckResult : AccessCheckResult
    {
        /// <summary>
        /// Service triggers for service.
        /// </summary>
        public IEnumerable<ServiceTriggerInformation> Triggers { get; }

        internal ServiceAccessCheckResult(string name, AccessMask granted_access, 
            SecurityDescriptor sd, TokenInformation token_info,
            IEnumerable<ServiceTriggerInformation> triggers) 
            : base(name, "Service", granted_access,
                ServiceUtils.GetServiceGenericMapping(), sd, 
                typeof(ServiceAccessRights), false, token_info)
        {
            Triggers = triggers;
        }
    }

    /// <summary>
    /// <para type="synopsis">Get a list of services openable by a specified token.</para>
    /// <para type="description">This cmdlet checks all services and tries to determine
    /// if one or more specified tokens can open them. If no tokens are specified then the 
    /// current process token is used.</para>
    /// </summary>
    /// <remarks>For best results this command should be run as an administrator.</remarks>
    /// <example>
    ///   <code>Get-AccessibleService</code>
    ///   <para>Check all accessible services for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleService -CheckScmAccess</code>
    ///   <para>Check access to the SCM for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleService -ProcessIds 1234,5678</code>
    ///   <para>>Check all accessible services for the process tokens of PIDs 1234 and 5678</para>
    /// </example>
    /// <example>
    ///   <code>$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low&#x0A;Get-AccessibleService -Tokens $token -AccessRights GenericWrite</code>
    ///   <para>Get all services which can be written by a low integrity copy of current token.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "AccessibleService", DefaultParameterSetName = "All")]
    [OutputType(typeof(AccessCheckResult))]
    public class GetAccessibleServiceCmdlet : CommonAccessBaseWithAccessCmdlet<ServiceAccessRights>
    {
        private RunningService GetServiceByName(string name)
        {
            try
            {
                return ServiceUtils.GetService(name);
            }
            catch (SafeWin32Exception ex)
            {
                WriteError(new ErrorRecord(ex, "OpenService", ErrorCategory.OpenError, name));
            }
            return null;
        }

        private IEnumerable<RunningService> GetServices()
        {
            if (Name != null && Name.Length > 0)
            {
                return Name.Select(n => GetServiceByName(n));
            }

            switch (CheckMode)
            {
                case ServiceCheckMode.ServiceOnly:
                    return ServiceUtils.GetServices();
                case ServiceCheckMode.DriverOnly:
                    return ServiceUtils.GetDrivers();
                case ServiceCheckMode.ServiceAndDriver:
                    return ServiceUtils.GetServicesAndDrivers();
                default:
                    throw new ArgumentException("Invalid check mode");
            }
        }

        /// <summary>
        /// <para type="description">Specify names of services to check.</para>
        /// </summary>
        [Parameter(Position = 0, ParameterSetName = "FromName")]
        public string[] Name { get; set; }

        /// <summary>
        /// <para type="description">Check access to the SCM.</para>
        /// </summary>
        [Parameter(ParameterSetName = "CheckScm")]
        public SwitchParameter CheckScmAccess { get; set; }

        /// <summary>
        /// <para type="description">Check mode for accessible services.</para>
        /// </summary>
        [Parameter(ParameterSetName = "All")]
        public ServiceCheckMode CheckMode { get; set; }

        internal override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
        {
            if (CheckScmAccess)
            {
                SecurityDescriptor sd = ServiceUtils.GetScmSecurityDescriptor();
                GenericMapping scm_mapping = ServiceUtils.GetScmGenericMapping();
                foreach (TokenEntry token in tokens)
                {
                    AccessMask granted_access = NtSecurity.GetMaximumAccess(sd, token.Token, scm_mapping);
                    WriteAccessCheckResult("SCM", "SCM", granted_access, scm_mapping, sd,
                        typeof(ServiceControlManagerAccessRights), false, token.Information);
                }
            }
            else
            {
                IEnumerable<RunningService> services = GetServices();

                GenericMapping service_mapping = ServiceUtils.GetServiceGenericMapping();
                AccessMask access_rights = service_mapping.MapMask(AccessRights);

                foreach (var service in services.Where(s => s?.SecurityDescriptor != null))
                {
                    foreach (TokenEntry token in tokens)
                    {
                        AccessMask granted_access = NtSecurity.GetMaximumAccess(service.SecurityDescriptor,
                            token.Token, service_mapping);
                        if (IsAccessGranted(granted_access, access_rights))
                        {
                            WriteObject(new ServiceAccessCheckResult(service.Name, granted_access,
                                service.SecurityDescriptor, token.Information, service.Triggers));
                        }
                    }
                }
            }
        }
    }
}
