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
using SandboxAnalysisUtils;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Management.Automation;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="description">Access check result for a service.</para>
    /// </summary>
    public class ServiceAccessCheckResult : AccessCheckResult
    {
        /// <summary>
        /// Service triggers for service.
        /// </summary>
        public IEnumerable<ServiceTriggerInformation> Triggers { get; private set; }

        internal ServiceAccessCheckResult(string name, AccessMask granted_access, 
            string sddl, TokenInformation token_info,
            IEnumerable<ServiceTriggerInformation> triggers) 
            : base(name, "Service", granted_access,
                ServiceUtils.GetServiceGenericMapping(), sddl, 
                typeof(ServiceAccessRights), false, token_info)
        {
            Triggers = triggers;
        }
    }

    /// <summary>
    /// <para type="synopsis">Get a list of services opened by a specified token.</para>
    /// <para type="description">This cmdlet checks all services and tries to determine
    /// if one or more specified tokens can open them to them. If no tokens are specified then the 
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
    ///   <para>Get all services with can be written by a low integrity copy of current token.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "AccessibleService")]
    [OutputType(typeof(AccessCheckResult))]
    public class GetAccessibleServiceCmdlet : CommonAccessBaseWithAccessCmdlet<ServiceAccessRights>
    {
        /// <summary>
        /// <para type="description">Specify names of services to check.</para>
        /// </summary>
        [Parameter(Position = 0)]
        public string[] Name { get; set; }

        /// <summary>
        /// <para type="description">Check access to the SCM.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter CheckScmAccess { get; set; }

        internal override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
        {
            if (CheckScmAccess)
            {
                SecurityDescriptor sd = ServiceUtils.GetScmSecurityDescriptor();
                GenericMapping scm_mapping = ServiceUtils.GetScmGenericMapping();
                foreach (TokenEntry token in tokens)
                {
                    AccessMask granted_access = NtSecurity.GetMaximumAccess(sd, token.Token, scm_mapping);
                    WriteAccessCheckResult("SCM", "SCM", granted_access, scm_mapping, sd.ToSddl(),
                        typeof(ServiceControlManagerAccessRights), false, token.Information);
                }
            }
            else
            {
                string[] names = Name;
                if (names == null || names.Length == 0)
                {
                    names = ServiceController.GetServices().Select(s => s.ServiceName).ToArray();
                }

                GenericMapping service_mapping = ServiceUtils.GetServiceGenericMapping();
                AccessMask access_rights = service_mapping.MapMask(AccessRights);

                foreach (string name in names)
                {
                    try
                    {
                        var service = ServiceUtils.GetServiceSecurityInformation(name);
                        foreach (TokenEntry token in tokens)
                        {
                            AccessMask granted_access = NtSecurity.GetMaximumAccess(service.SecurityDescriptor,
                                token.Token, service_mapping);
                            if (IsAccessGranted(granted_access, access_rights))
                            {
                                WriteObject(new ServiceAccessCheckResult(name, granted_access,
                                    service.SecurityDescriptor.ToSddl(), token.Information, service.Triggers));
                            }
                        }
                    }
                    catch (Win32Exception ex)
                    {
                        WriteError(new ErrorRecord(ex, "OpenService", ErrorCategory.OpenError, name));
                    }
                }
            }
        }
    }
}
