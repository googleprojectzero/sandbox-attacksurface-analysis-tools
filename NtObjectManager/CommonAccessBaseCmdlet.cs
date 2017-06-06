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
    /// Class to represent an access check result.
    /// </summary>
    public class AccessCheckResult
    {
        /// <summary>
        /// The name of the object which was accessed (depends on the type).
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Named of the type accessed.
        /// </summary>
        public string TypeName { get; private set; }
        
        /// <summary>
        /// Granted access.
        /// </summary>
        public AccessMask GrantedAccess { get; private set; }

        /// <summary>
        /// Get granted access as a type specific string
        /// </summary>
        public string GrantedAccessString { get; private set; }

        /// <summary>
        /// Get granted access as generic access string.
        /// </summary>
        public string GrantedGenericAccessString { get; private set; }

        /// <summary>
        /// The generic mapping associated with this type.
        /// </summary>
        public GenericMapping GenericMapping { get; private set; }

        /// <summary>
        /// The security descriptor associated with this access check.
        /// </summary>
        public string SecurityDescriptor { get; private set; }

        /// <summary>
        /// Process ID for access check result.
        /// </summary>
        public int ProcessId { get; private set; }

        /// <summary>
        /// Name of process for access check result.
        /// </summary>
        public string ProcessName { get; private set; }

        /// <summary>
        /// Image path for process.
        /// </summary>
        public string ProcessImagePath { get; private set; }

        /// <summary>
        /// Image path for process.
        /// </summary>
        public string ProcessCommandLine { get; private set; }

        /// <summary>
        /// Was read access granted?
        /// </summary>
        public bool IsRead { get; private set; }

        /// <summary>
        /// Was write access granted?
        /// </summary>
        public bool IsWrite { get; private set; }

        /// <summary>
        /// Was execute access granted?
        /// </summary>
        public bool IsExecute { get; private set; }

        /// <summary>
        /// Was all access granted?
        /// </summary>
        public bool IsAll { get; private set; }

        /// <summary>
        /// A unique key to correlate access checks.
        /// </summary>
        public Guid Key { get; private set; }

        internal AccessCheckResult(string name, string type_name, AccessMask granted_access, 
            GenericMapping generic_mapping, string sddl, Type enum_type, ProcessInformation proc_info)
        {
            Name = name;
            TypeName = type_name;
            GrantedAccess = granted_access;
            GenericMapping = generic_mapping;
            ProcessId = proc_info.ProcessId;
            ProcessName = proc_info.Name;
            ProcessImagePath = proc_info.ImagePath;
            ProcessCommandLine = proc_info.CommandLine;
            Key = proc_info.Key;
            SecurityDescriptor = sddl;
            IsRead = generic_mapping.HasRead(granted_access);
            IsWrite = generic_mapping.HasWrite(granted_access);
            IsExecute = generic_mapping.HasExecute(granted_access);
            IsAll = generic_mapping.HasAll(granted_access);
            GrantedAccessString = NtObjectUtils.GrantedAccessAsString(granted_access, generic_mapping, enum_type, false);
            GrantedGenericAccessString = NtObjectUtils.GrantedAccessAsString(granted_access, generic_mapping, enum_type, true);
        }
    }

    internal sealed class ProcessInformation : IDisposable
    {
        public int ProcessId { get; private set; }
        public string Name { get; private set; }
        public string ImagePath { get; private set; }
        public string CommandLine { get; private set; }
        public NtToken Token { get; private set; }
        public Guid Key { get; private set; }

        void IDisposable.Dispose()
        {
            Token?.Close();
        }

        internal ProcessInformation(int pid)
        {
            using (NtProcess proc = NtProcess.Open(pid, ProcessAccessRights.QueryLimitedInformation))
            {
                ProcessId = pid;
                Name = proc.Name;
                ImagePath = proc.GetImageFilePath(false);
                CommandLine = proc.CommandLine;
                Token = NtToken.OpenProcessToken(proc, true, TokenAccessRights.MaximumAllowed);
                Key = Guid.NewGuid();
            }
        }
    }

    /// <summary>
    /// Common base cmdlet for commands which look at accessible resources.
    /// </summary>
    public abstract class CommonAccessBaseCmdlet : Cmdlet
    {
        /// <summary>
        /// <para type="description">Specify a list of process IDs to open for their tokens.</para>
        /// </summary>
        [Parameter]
        public int[] ProcessIds { get; set; }

        /// <summary>
        /// <para type="description">Specify a list of process names to open for their tokens.</para>
        /// </summary>
        [Parameter]
        public string[] ProcessNames { get; set; }

        /// <summary>
        /// <para type="description">Specify a list of command lines to filter on find for the process tokens.</para>
        /// </summary>
        [Parameter]
        public string[] ProcessCommandLines { get; set; }

        internal abstract void RunAccessCheck(IList<ProcessInformation> processes);

        internal void WriteAccessCheckResult(string name, string type_name, AccessMask granted_access,
            GenericMapping generic_mapping, string sddl, Type enum_type, ProcessInformation proc_info)
        {
            WriteObject(new AccessCheckResult(name, type_name, granted_access, generic_mapping, sddl, enum_type, proc_info));
        }

        private IEnumerable<int> PidsFromArguments(string[] names, string[] cmdlines)
        {
            HashSet<string> names_set = new HashSet<string>(names ?? new string[0], StringComparer.OrdinalIgnoreCase);
            HashSet<string> cmdline_set = new HashSet<string>(cmdlines ?? new string[0], StringComparer.OrdinalIgnoreCase);
            HashSet<int> pid_set = new HashSet<int>();

            if (names_set.Count > 0 || cmdline_set.Count > 0)
            {
                using (var procs = NtProcess.GetProcesses(ProcessAccessRights.QueryLimitedInformation).ToDisposableList())
                {
                    foreach (NtProcess proc in procs)
                    {
                        try
                        {
                            if (names_set.Contains(proc.Name))
                            {
                                pid_set.Add(proc.ProcessId);
                            }
                            else
                            {
                                string curr_cmdline = proc.CommandLine.ToLower();
                                foreach (string cmdline in cmdlines)
                                {
                                    if (curr_cmdline.Contains(cmdline.ToLower()))
                                    {
                                        pid_set.Add(proc.ProcessId);
                                        break;
                                    }
                                }
                            }
                        }
                        catch (NtException)
                        {
                        }
                    }
                }
            }
            return pid_set;
        }

        /// <summary>
        /// Overridden process record method.
        /// </summary>
        protected override void ProcessRecord()
        {
            IEnumerable<int> pids_total = ProcessIds ?? new int[0];
            pids_total = pids_total.Concat(PidsFromArguments(ProcessNames, ProcessCommandLines));
            HashSet<int> pids = new HashSet<int>(pids_total);
            if (pids.Count == 0)
            {
                pids.Add(NtProcess.Current.ProcessId);
            }

            NtToken.EnableDebugPrivilege();
            using (DisposableList<ProcessInformation> procs = new DisposableList<ProcessInformation>())
            {
                procs.AddRange(pids.Select(pid => new ProcessInformation(pid)));
                
                RunAccessCheck(procs);
            }
        }
    }
}
