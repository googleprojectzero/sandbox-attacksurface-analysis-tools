//  Copyright 2019 Google Inc. All Rights Reserved.
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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Management.Automation;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="description">Access check result for a scheduled task.</para>
    /// </summary>
    public class ScheduledTaskAccessCheckResult : AccessCheckResult
    {
        private static readonly NtType _file_type = NtType.GetTypeByType<NtFile>();

        /// <summary>
        /// Whether the task is enabled.
        /// </summary>
        public bool Enabled { get; }

        internal ScheduledTaskAccessCheckResult(ManagementObject task, string name, AccessMask granted_access,
            string sddl, TokenInformation token_info)
            : base(name, "Scheduled Task", granted_access,
                _file_type.GenericMapping, sddl,
                typeof(FileAccessRights), false, token_info)
        {
        }
    }

    /// <summary>
    /// <para type="synopsis">Get a list of scheduled tasks openable by a specified token.</para>
    /// <para type="description">This cmdlet checks all scheduled tasks and tries to determine
    /// if one or more specified tokens can open them. If no tokens are specified then the 
    /// current process token is used.</para>
    /// </summary>
    /// <remarks>For best results this command should be run as an administrator.</remarks>
    /// <example>
    ///   <code>Get-AccessibleScheduledTask</code>
    ///   <para>Check all accessible scheduled tasks for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleScheduledTask -ProcessIds 1234,5678</code>
    ///   <para>>Check all accessible scheduled tasks for the process tokens of PIDs 1234 and 5678</para>
    /// </example>
    /// <example>
    ///   <code>$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low&#x0A;Get-AccessibleScheduledTask -Tokens $token -AccessRights GenericWrite</code>
    ///   <para>Get all scheduled tasks which can be written by a low integrity copy of current token.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "AccessibleScheduledTask")]
    [OutputType(typeof(ScheduledTaskAccessCheckResult))]
    public class GetAccessibleScheduledTaskCmdlet : CommonAccessBaseWithAccessCmdlet<FileAccessRights>
    {
        private static readonly NtType _file_type = NtType.GetTypeByType<NtFile>();

        internal override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
        {
            foreach (var obj in GetScheduledTasks())
            {
                string name = obj["TaskName"] as string;
                string path = obj["TaskPath"] as string;
                string sddl = obj["SecurityDescriptor"] as string;
                if (string.IsNullOrWhiteSpace(sddl) || string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(path))
                {
                    continue;
                }

                AccessMask access_rights = _file_type.GenericMapping.MapMask(AccessRights);
                foreach (TokenEntry token in tokens)
                {
                    SecurityDescriptor sd = new SecurityDescriptor(sddl);
                    if (sd.Owner == null)
                    {
                        sd.Owner = new SecurityDescriptorSid(KnownSids.BuiltinAdministrators, false);
                    }
                    if (sd.Group == null)
                    {
                        sd.Group = new SecurityDescriptorSid(KnownSids.BuiltinAdministrators, false);
                    }

                    AccessMask granted_access = NtSecurity.GetMaximumAccess(sd,
                        token.Token, _file_type.GenericMapping);
                    if (IsAccessGranted(granted_access, access_rights))
                    {
                        WriteObject(new ScheduledTaskAccessCheckResult(obj, Path.Combine(path, name), 
                            granted_access, sddl, token.Information));
                    }
                }
            }
        }

        private IEnumerable<ManagementObject> GetScheduledTasks()
        {
	        ManagementClass tasks = new ManagementClass(@"\\.\ROOT\Microsoft\Windows\TaskScheduler:MSFT_ScheduledTask");
            return tasks.GetInstances().OfType<ManagementObject>();
        }
    }
}
