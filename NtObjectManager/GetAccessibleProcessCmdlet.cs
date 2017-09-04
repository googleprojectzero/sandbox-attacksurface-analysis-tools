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
        /// <summary>
        /// Session ID of the process.
        /// </summary>
        public int SessionId { get; private set; }

        /// <summary>
        /// Gets whether this is a thread access check result.
        /// </summary>
        public bool IsThread { get; private set; }

        internal ProcessAccessCheckResult(string name, string image_path, int process_id, int session_id,
            string command_line, AccessMask granted_access, bool is_thread,
            NtType type, string sddl, TokenInformation token_info) : base(name, type.Name, granted_access, 
                type.GenericMapping, sddl, type.AccessRightsType, false, token_info)
        {
            ProcessImagePath = image_path;
            ProcessId = process_id;
            ProcessCommandLine = command_line;
            IsThread = is_thread;
            SessionId = session_id;
        }
    }

    /// <summary>
    /// Access check result for a thread.
    /// </summary>
    public class ThreadAccessCheckResult : ProcessAccessCheckResult
    {
        /// <summary>
        /// Thread ID of the thread.
        /// </summary>
        public int ThreadId { get; private set; }

        /// <summary>
        /// Thread description if available.
        /// </summary>
        public string ThreadDescription { get; private set; }

        internal ThreadAccessCheckResult(string name, string image_path, int thread_id, string thread_description, int process_id, 
            int session_id, string command_line, AccessMask granted_access,
            NtType type, string sddl, TokenInformation token_info) : base(String.Format("{0}/{1}.{2}", name, process_id, thread_id), 
                image_path, process_id, session_id, command_line, granted_access,
                true, type, sddl, token_info)
        {
            ThreadId = thread_id;
            ThreadDescription = thread_description;
        }
    }

    /// <summary>
    /// <para type="description">Specify what objects to query for.</para>
    /// </summary>
    public enum ProcessCheckMode
    {
        /// <summary>
        /// Only check processes
        /// </summary>
        ProcessOnly,
        /// <summary>
        /// Only check threads.
        /// </summary>
        ThreadOnly,
        /// <summary>
        /// Check both processes and threads.
        /// </summary>
        ProcessAndThread
    }

    /// <summary>
    /// <para type="synopsis">Get a list of processes and/or threads that can be opened by a specified token.</para>
    /// <para type="description">This cmdlet checks all processes and threads and tries to determine
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
    public class GetAccessibleProcessCmdlet : CommonAccessBaseWithAccessCmdlet<ProcessAccessRights>
    {
        private static NtType _process_type = NtType.GetTypeByType<NtProcess>();
        private static NtType _thread_type = NtType.GetTypeByType<NtThread>();

        /// <summary>
        /// <para type="description">Specify what objects to check for.</para>
        /// </summary>
        [Parameter]
        public ProcessCheckMode CheckMode { get; set; }

        /// <summary>
        /// <para type="description">Specify specific access rights for threads.</para>
        /// </summary>
        [Parameter]
        public ThreadAccessRights ThreadAccessRights { get; set; }

        /// <summary>
        /// <para type="description">Specify that dead processes should be shown.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter ShowDeadProcesses { get; set; }

        class ProcessDetails
        {
            public string Name { get; set; }
            public string ImagePath { get; set; }
            public string CommandLine { get; set; }
            public int ProcessId { get; set; }
            public int SessionId { get; set; }

            private ProcessDetails()
            {
            }

            public static ProcessDetails FromProcess(NtProcess process)
            {
                string name = process.Name;
                string image_path = process.FullPath;
                string command_line = "Unknown";
                int process_id = -1;
                int session_id = 0;

                if (process.IsAccessGranted(ProcessAccessRights.QueryLimitedInformation))
                {
                    command_line = process.CommandLine;
                    process_id = process.ProcessId;
                    session_id = process.SessionId;
                }
                else
                {
                    using (var dup_process = process.Duplicate(ProcessAccessRights.QueryLimitedInformation, AttributeFlags.None, DuplicateObjectOptions.None, false))
                    {
                        if (dup_process.IsSuccess)
                        {
                            command_line = dup_process.Result.CommandLine;
                            process_id = dup_process.Result.ProcessId;
                            session_id = dup_process.Result.SessionId;
                        }
                    }
                }
                return new ProcessDetails() { Name = name, ImagePath = image_path,
                    CommandLine = command_line, ProcessId = process_id, SessionId = session_id };
            }

            public static ProcessDetails FromThread(NtThread thread)
            {
                return new ProcessDetails()
                {
                    Name = thread.ProcessName,
                    ImagePath = String.Empty,
                    CommandLine = String.Empty,
                    ProcessId = thread.ProcessId
                };
            }
        }

        class ThreadDetails
        {
            public string Description { get; set; }
            public int ThreadId { get; set; }

            public static ThreadDetails FromThread(NtThread thread)
            {
                string description = String.Empty;
                int thread_id = -1;

                if (thread.IsAccessGranted(ThreadAccessRights.QueryLimitedInformation))
                {
                    description = thread.Description;
                    thread_id = thread.ThreadId;
                }
                else
                {
                    using (var dup_thread = thread.Duplicate(ThreadAccessRights.QueryLimitedInformation, 
                        AttributeFlags.None, DuplicateObjectOptions.None, false))
                    {
                        if (dup_thread.IsSuccess)
                        {
                            description = dup_thread.Result.Description;
                            thread_id = dup_thread.Result.ThreadId;
                        }
                    }
                }
                return new ThreadDetails()
                {
                    Description = description,
                    ThreadId = thread_id
                };
            }
        }

        private void WriteAccessCheckResult(ProcessDetails process, ThreadDetails thread, AccessMask granted_access,
           GenericMapping generic_mapping, string sddl, TokenInformation token)
        {
            if (thread == null)
            {
                WriteObject(new ProcessAccessCheckResult(process.Name, process.ImagePath, process.ProcessId, process.SessionId, 
                    process.CommandLine, granted_access, false, _process_type, sddl, token));
            }
            else
            {
                WriteObject(new ThreadAccessCheckResult(process.Name, process.ImagePath, thread.ThreadId, 
                    thread.Description, process.ProcessId, process.SessionId, process.CommandLine, granted_access, _thread_type, sddl, token));
            }
        }

        private void CheckAccess(TokenEntry token, ProcessDetails process, ThreadDetails thread, NtType type, AccessMask access_rights, SecurityDescriptor sd)
        {
            AccessMask granted_access = NtSecurity.GetMaximumAccess(sd, token.Token, type.GenericMapping);
            if (IsAccessGranted(granted_access, access_rights))
            {
                WriteAccessCheckResult(process, thread, granted_access, type.GenericMapping, sd.ToSddl(), token.Information);
            }
        }

        private bool CheckProcess()
        {
            return CheckMode == ProcessCheckMode.ProcessOnly || CheckMode == ProcessCheckMode.ProcessAndThread;
        }

        private bool CheckThread()
        {
            return CheckMode == ProcessCheckMode.ThreadOnly || CheckMode == ProcessCheckMode.ProcessAndThread;
        }

        private void DoAccessCheck(IEnumerable<TokenEntry> tokens,
            ProcessDetails proc_details, NtThread thread, AccessMask access_rights)
        {
            var sd = thread.GetSecurityDescriptor(SecurityInformation.AllBasic, false);
            if (sd.IsSuccess)
            {
                foreach (TokenEntry token in tokens)
                {
                    CheckAccess(token, proc_details, ThreadDetails.FromThread(thread), _thread_type, access_rights, sd.Result);
                }
            }
            else
            {
                // Try and open process when under impersonation.
                foreach (TokenEntry token in tokens)
                {
                    using (var new_thread = token.Token.RunUnderImpersonate(() => NtThread.Open(thread.ThreadId, ThreadAccessRights.MaximumAllowed, false)))
                    {
                        if (new_thread.IsSuccess && IsAccessGranted(new_thread.Result.GrantedAccessMask, access_rights))
                        {
                            WriteAccessCheckResult(proc_details, ThreadDetails.FromThread(thread), new_thread.Result.GrantedAccessMask,
                                _thread_type.GenericMapping, String.Empty, token.Information);
                        }
                    }
                }
            }
        }

        private void DoAccessCheck(IEnumerable<TokenEntry> tokens, 
            IEnumerable<NtProcess> processes, AccessMask access_rights, AccessMask thread_access_rights)
        {
            foreach (NtProcess process in processes)
            {
                ProcessDetails proc_details = ProcessDetails.FromProcess(process);

                if (CheckProcess())
                {
                    var sd = process.GetSecurityDescriptor(SecurityInformation.AllBasic, false);
                    if (sd.IsSuccess)
                    {
                        foreach (TokenEntry token in tokens)
                        {
                            CheckAccess(token, proc_details, null, _process_type, access_rights, sd.Result);
                        }
                    }
                    else
                    {
                        // Try and open process when under impersonation.
                        foreach (TokenEntry token in tokens)
                        {
                            using (var new_process = token.Token.RunUnderImpersonate(() => NtProcess.Open(process.ProcessId, ProcessAccessRights.MaximumAllowed, false)))
                            {
                                if (new_process.IsSuccess && IsAccessGranted(new_process.Result.GrantedAccessMask, access_rights))
                                {
                                    WriteAccessCheckResult(proc_details, null, new_process.Result.GrantedAccessMask,
                                        _process_type.GenericMapping, String.Empty, token.Information);
                                }
                            }
                        }
                    }
                }

                if (CheckThread())
                {
                    using (var threads = process.GetThreads(ThreadAccessRights.MaximumAllowed).ToDisposableList())
                    {
                        foreach (var thread in threads)
                        {
                            DoAccessCheck(tokens, proc_details, thread, thread_access_rights);
                        }
                    }
                }
            }
        }

        internal override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
        {
            AccessMask access_rights = _process_type.MapGenericRights(AccessRights);
            AccessMask thread_access_rights = _thread_type.MapGenericRights(ThreadAccessRights);
            
            if (!NtToken.EnableDebugPrivilege())
            {
                WriteWarning("Current process doesn't have SeDebugPrivilege, results may be inaccurate");
            }

            if (CheckProcess())
            {
                using (var procs = NtProcess.GetProcesses(ProcessAccessRights.MaximumAllowed, false).ToDisposableList())
                {
                    DoAccessCheck(tokens, procs.Where(p => ShowDeadProcesses || !p.IsDeleting), access_rights, thread_access_rights);
                }
            }
            else
            {
                using (var threads = NtThread.GetThreads(ThreadAccessRights.MaximumAllowed, true).ToDisposableList())
                {
                    foreach (var thread in threads)
                    {
                        DoAccessCheck(tokens, ProcessDetails.FromThread(thread), thread, thread_access_rights);
                    }
                }
            }
        }
    }
}
