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
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="synopsis">Get a list of ALPC Ports that can be opened by a specificed token.</para>
    /// <para type="description">This cmdlet checks for all ALPC ports on the system and tries to determine
    /// if one or more specified tokens can connect to them. If no token are specified then the current 
    /// process token is used.</para>
    /// </summary>
    /// <example>
    ///   <code>Get-AccessibleAlpcPort</code>
    ///   <para>Get all accessible ALPC ports for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleAlpcPort -ProcessIds 1234,5678</code>
    ///   <para>Get all accessible ALPC ports for the process tokens of PIDs 1234 and 5678</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "AccessibleAlpcPort")]
    public class GetAccessibleAlpcPortCmdlet : CommonAccessBaseCmdlet
    {
        internal override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
        {
            IEnumerable<NtHandle> handles = NtSystemInfo.GetHandles(-1, false);
            HashSet<ulong> checked_objects = new HashSet<ulong>();
            NtType alpc_type = NtType.GetTypeByType<NtAlpc>();
            handles = handles.Where(h => h.ObjectType.Equals(alpc_type.Name, StringComparison.OrdinalIgnoreCase));
            Dictionary<int, NtProcess> pid_to_process = new Dictionary<int, NtProcess>();
            HashSet<string> ports = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                foreach (NtHandle handle in handles.Where(h => h.GrantedAccess.IsAccessGranted(GenericAccessRights.ReadControl)))
                {
                    if (!pid_to_process.ContainsKey(handle.ProcessId))
                    {
                        try
                        {
                            pid_to_process[handle.ProcessId] = NtProcess.Open(handle.ProcessId,
                                ProcessAccessRights.QueryLimitedInformation | ProcessAccessRights.DupHandle);
                        }
                        catch (NtException)
                        {
                            pid_to_process[handle.ProcessId] = null;
                        }
                    }

                    NtProcess proc = pid_to_process[handle.ProcessId];
                    if (proc == null)
                    {
                        continue;
                    }

                    try
                    {
                        
                        using (NtAlpc obj = NtAlpc.DuplicateFrom(proc, new IntPtr(handle.Handle)))
                        {
                            string name = obj.FullPath;
                            // We only care about named ALPC ports.
                            if (String.IsNullOrEmpty(name))
                            {
                                continue;
                            }

                            if (!ports.Add(name))
                            {
                                continue;
                            }

                            SecurityDescriptor sd = obj.SecurityDescriptor;
                            string sddl = sd.ToSddl();
                            foreach (TokenEntry token in tokens)
                            {
                                AccessMask granted_access = NtSecurity.GetAllowedAccess(sd, token.Token,
                                    AlpcAccessRights.Connect, alpc_type.GenericMapping);
                                if (granted_access.IsEmpty)
                                {
                                    continue;
                                }
                                AccessMask maximum_access = NtSecurity.GetMaximumAccess(sd,
                                    token.Token, alpc_type.GenericMapping);
                                WriteAccessCheckResult(name, alpc_type.Name, maximum_access, 
                                    alpc_type.GenericMapping, sddl, typeof(AlpcAccessRights), token.Information);
                            }
                        }
                    }
                    catch (NtException)
                    {
                    }
                }
            }
            finally
            {
                foreach (NtProcess proc in pid_to_process.Values)
                {
                    proc?.Close();
                }
            }
        }
    }
}
