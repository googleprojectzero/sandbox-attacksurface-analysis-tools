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
using System;
using System.Collections.Generic;
using System.Management.Automation;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="description">Access check result for a process.</para>
    /// </summary>
    public class ProcessAccessCheckResult : AccessCheckResult
    {
        /// <summary>
        /// Process image path.
        /// </summary>
        public string ProcessImagePath { get; private set; }
        /// <summary>
        /// Process ID of the process.
        /// </summary>
        public int ProcessId { get; private set; }
        /// <summary>
        /// Command line of the process.
        /// </summary>
        public string ProcessCommandLine { get; private set; }

        internal ProcessAccessCheckResult(string name, string image_path, int process_id, string command_line, AccessMask granted_access,
            NtType type, string sddl, TokenInformation token_info) : base(name, type.Name, granted_access, 
                type.GenericMapping, sddl, typeof(ProcessAccessRights), token_info)
        {
            ProcessImagePath = image_path;
            ProcessId = process_id;
            ProcessCommandLine = command_line;
        }
    }

    /// <summary>
    /// <para type="synopsis">Get a list of processes that can be opened by a specificed token.</para>
    /// <para type="description">This cmdlet checks all processes and tries to determine
    /// if one or more specified tokens can open them to them. If no tokens are specified then the 
    /// current process token is used.</para>
    /// </summary>
    /// <remarks>For best results this command should be run as an administrator with SeDebugPrivilege.</remarks>
    /// <example>
    ///   <code>Get-AccessibleProcess</code>
    ///   <para>Check all accessible processes for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleProcess -ProcessIds 1234,5678</code>
    ///   <para>>Check all accessible processes for the process tokens of PIDs 1234 and 5678</para>
    /// </example>
    /// <example>
    ///   <code>$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low&#x0A;Get-AccessibleProcess -Tokens $token -AccessRights GenericWrite</code>
    ///   <para>Get all processes with can be written by a low integrity copy of current token.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "AccessibleProcess")]
    [OutputType(typeof(ProcessAccessCheckResult))]
    public class GetAccessibleProcessCmdlet : CommonAccessBaseCmdlet<ProcessAccessRights>
    {
        /// <summary>
        /// <para type="description">When getting all processes only get the system information process list.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter FromSystem { get; set; }

        internal void WriteAccessCheckResult(NtProcess process, AccessMask granted_access,
           GenericMapping generic_mapping, string sddl, TokenInformation token)
        {
            string name = process.Name;
            string image_path = process.FullPath;
            string command_line = "Unknown";
            int process_id = -1;

            if (process.IsAccessGranted(ProcessAccessRights.QueryLimitedInformation))
            {
                command_line = process.CommandLine;
                process_id = process.ProcessId;
            }
            else
            {
                try
                {
                    using (NtProcess dup_process = process.Duplicate(ProcessAccessRights.QueryLimitedInformation))
                    {
                        command_line = dup_process.CommandLine;
                        process_id = dup_process.ProcessId;
                    }
                }
                catch (NtException)
                {
                }
            }

            WriteObject(new ProcessAccessCheckResult(name, image_path, process_id, command_line, 
                granted_access, process.NtType, sddl, token));
        }

        private void CheckAccess(TokenEntry token, NtProcess process, AccessMask access_rights, SecurityDescriptor sd)
        {
            NtType type = process.NtType;
            AccessMask granted_access = NtSecurity.GetMaximumAccess(sd, token.Token, type.GenericMapping);
            if (IsAccessGranted(granted_access, access_rights))
            {
                WriteAccessCheckResult(process, granted_access, type.GenericMapping, sd.ToSddl(), token.Information);
            }
        }

        private void CheckAccessWithReadControl(IEnumerable<TokenEntry> tokens, IEnumerable<NtProcess> processes, AccessMask access_rights)
        {
            foreach (NtProcess process in processes)
            {
                SecurityDescriptor sd = process.SecurityDescriptor;
                foreach (TokenEntry token in tokens)
                {
                    CheckAccess(token, process, access_rights, sd);
                }
            }
        }

        internal override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
        {
            AccessMask access_rights = NtType.GetTypeByType<NtProcess>().MapGenericRights(AccessRights);
            // If we've got debug privilege we can open all processes and get their security descriptors.
            // So we can just do a standard access check against each token. 
            if (NtToken.EnableDebugPrivilege())
            {
                using (var procs = NtProcess.GetProcesses(ProcessAccessRights.ReadControl | ProcessAccessRights.QueryInformation, FromSystem).ToDisposableList())
                {
                    CheckAccessWithReadControl(tokens, procs, access_rights);
                }
            }
            else
            {
                WriteWarning("Current process doesn't have SeDebugPrivilege, results may be inaccurate");
                // We'll have to open each process in turn to see what we can access.
                foreach (var token in tokens)
                {
                    using (var processes = new DisposableList<NtProcess>())
                    {
                        using (token.Token.Impersonate())
                        {
                            processes.AddRange(NtProcess.GetProcesses(ProcessAccessRights.MaximumAllowed, FromSystem));
                        }
                        foreach (NtProcess process in processes)
                        {
                            if (IsAccessGranted(process.GrantedAccess, access_rights))
                            {
                                WriteAccessCheckResult(process, process.GrantedAccessMask,
                                    process.NtType.GenericMapping, String.Empty, token.Information);
                            }
                        }
                    }
                }
            }
        }
    }
}
