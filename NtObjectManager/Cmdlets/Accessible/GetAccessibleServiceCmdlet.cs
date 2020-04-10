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
using System.IO;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Accessible
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
        public RunningService Service { get; }

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
            RunningService service) 
            : base(name, "Service", granted_access,
                ServiceUtils.GetServiceGenericMapping(), sd, 
                typeof(ServiceAccessRights), false, token_info)
        {
            TriggerGrantedAccess = trigger_granted_access;
            OriginalGrantedAccess = original_granted_access;
            Service = service;
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
    ///   <code>Get-AccessibleService -CheckFiles</code>
    ///   <para>Check all accessible services for the current process token as well as generating access checks for the services files.</para>
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
    [OutputType(typeof(CommonAccessCheckResult))]
    public class GetAccessibleServiceCmdlet : CommonAccessBaseWithAccessCmdlet<ServiceAccessRights>
    {
        private class InternalGetAccessibleFileCmdlet : GetAccessibleFileCmdlet
        {
            private GetAccessibleServiceCmdlet _cmdlet;

            public InternalGetAccessibleFileCmdlet(GetAccessibleServiceCmdlet cmdlet)
            {
                _cmdlet = cmdlet;
                FormatWin32Path = true;
            }

            private protected override void WriteAccessCheckResult(string name, string type_name, AccessMask granted_access, GenericMapping generic_mapping, SecurityDescriptor sd, Type enum_type, bool is_directory, TokenInformation token_info)
            {
                _cmdlet.WriteAccessCheckResult(name, type_name, granted_access, generic_mapping, sd, enum_type, is_directory, token_info);
            }

            internal void RunAccessCheckPathInternal(IEnumerable<TokenEntry> tokens, string path)
            {
                RunAccessCheckPath(tokens, NtFileUtils.DosFileNameToNt(path));
            }
        }

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

        private bool CheckForAccess<T>(SecurityDescriptor sd, NtToken token, T desired_access, GenericMapping generic_mapping) where T : Enum
        {
            var result = NtSecurity.AccessCheck(sd, token,
                               desired_access, null, generic_mapping, false);
            if (!result.IsSuccess || !result.Result.Status.IsSuccess())
            {
                return false;
            }
            return result.Result.GrantedAccess.HasAccess;
        }

        private ServiceAccessRights GetTriggerAccess(RunningService service, NtToken token)
        {
            if (IgnoreTrigger)
                return 0;

            ServiceAccessRights granted_access = 0;
            NtType type = NtType.GetTypeByType<NtEtwRegistration>();

            foreach (var trigger in service.Triggers)
            {
                bool accessible = false;
                if (trigger.TriggerType == ServiceTriggerType.NetworkEndpoint)
                {
                    accessible = true;
                }
                else if (trigger is EtwServiceTriggerInformation etw_trigger)
                {
                    if (etw_trigger.SecurityDescriptor == null)
                    {
                        WriteWarning($"Can't access ETW Security Descriptor for service {service.Name}. Running as Administrator might help.");
                    }
                    else
                    {
                        accessible = CheckForAccess(etw_trigger.SecurityDescriptor, token,
                            TraceAccessRights.GuidEnable, type.GenericMapping);
                    }
                }
                else if (trigger is WnfServiceTriggerInformation wnf_trigger)
                {
                    if (wnf_trigger.Name?.SecurityDescriptor == null)
                    {
                        WriteWarning($"Can't access WNF Security Descriptor for service {service.Name}");
                    }
                    else
                    {
                        accessible = CheckForAccess(wnf_trigger.Name.SecurityDescriptor, token,
                            WnfAccessRights.WriteData, NtWnf.GenericMapping);
                    }
                }

                if (accessible)
                {
                    if (trigger.Action == ServiceTriggerAction.Start)
                    {
                        granted_access |= ServiceAccessRights.Start;
                    }
                    else
                    {
                        granted_access |= ServiceAccessRights.Stop;
                    }
                }
            }

            return granted_access;
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

        /// <summary>
        /// <para type="description">Ignore triggers when checking maximum access.</para>
        /// </summary>
        [Parameter(ParameterSetName = "All")]
        [Parameter(ParameterSetName = "FromName")]
        public SwitchParameter IgnoreTrigger { get; set; }

        /// <summary>
        /// <para type="description">Generate access check results for the service files.</para>
        /// </summary>
        [Parameter(ParameterSetName = "All")]
        [Parameter(ParameterSetName = "FromName")]
        public SwitchParameter CheckFiles { get; set; }

        private protected override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
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
                InternalGetAccessibleFileCmdlet file_cmdlet = null;
                HashSet<string> checked_files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (CheckFiles)
                {
                    file_cmdlet = new InternalGetAccessibleFileCmdlet(this)
                    {
                        FormatWin32Path = true
                    };
                }

                GenericMapping service_mapping = ServiceUtils.GetServiceGenericMapping();
                AccessMask access_rights = service_mapping.MapMask(Access);

                foreach (var service in services.Where(s => s?.SecurityDescriptor != null))
                {
                    foreach (TokenEntry token in tokens)
                    {
                        AccessMask granted_access = NtSecurity.GetMaximumAccess(service.SecurityDescriptor,
                            token.Token, service_mapping);
                        ServiceAccessRights trigger_access = GetTriggerAccess(service, token.Token);
                        if (IsAccessGranted(granted_access, access_rights))
                        {
                            WriteObject(new ServiceAccessCheckResult(service.Name, granted_access | trigger_access,
                                service.SecurityDescriptor, token.Information, trigger_access,
                                granted_access.ToSpecificAccess<ServiceAccessRights>(), service));
                        }
                    }
                    if (CheckFiles)
                    {
                        if (!string.IsNullOrWhiteSpace(service.ImagePath) 
                            && File.Exists(service.ImagePath) 
                            && checked_files.Add(service.ImagePath))
                        {
                            file_cmdlet.RunAccessCheckPathInternal(tokens, service.ImagePath);
                        }

                        if (!string.IsNullOrWhiteSpace(service.ServiceDll) 
                            && File.Exists(service.ServiceDll) 
                            && checked_files.Add(service.ServiceDll))
                        {
                            file_cmdlet.RunAccessCheckPathInternal(tokens, service.ServiceDll);
                        }
                    }
                }
            }
        }
    }
}
