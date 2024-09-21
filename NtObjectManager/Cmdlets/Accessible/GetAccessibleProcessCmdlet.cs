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

using NtCoreLib;
using NtCoreLib.Security;
using NtCoreLib.Security.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// <para type="description">Access check result for a process.</para>
/// </summary>
public class ProcessAccessCheckResult : CommonAccessCheckResult
{
    /// <summary>
    /// Process image path.
    /// </summary>
    public string ProcessImagePath { get; }
    /// <summary>
    /// Process ID of the process.
    /// </summary>
    public int ProcessId { get; }
    /// <summary>
    /// Command line of the process.
    /// </summary>
    public string ProcessCommandLine { get; }
    /// <summary>
    /// Session ID of the process.
    /// </summary>
    public int SessionId { get; }
    /// <summary>
    /// Gets whether this is a thread access check result.
    /// </summary>
    public bool IsThread { get; }
    /// <summary>
    /// Gets the user SID for the process.
    /// </summary>
    public string User { get; }
    /// <summary>
    /// Gets whether the process was dead.
    /// </summary>
    public bool IsDead { get; }

    internal ProcessAccessCheckResult(string name, string image_path, int process_id, int session_id,
        string command_line, AccessMask granted_access, bool is_thread, bool is_dead, string user,
        NtType type, SecurityDescriptor sd, TokenInformation token_info) : base(name, type.Name, granted_access, 
            type.GenericMapping, sd, type.AccessRightsType, false, token_info)
    {
        ProcessImagePath = image_path;
        ProcessId = process_id;
        ProcessCommandLine = command_line;
        IsThread = is_thread;
        IsDead = is_dead;
        SessionId = session_id;
        User = user;
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
    public int ThreadId { get; }

    /// <summary>
    /// Thread description if available.
    /// </summary>
    public string ThreadDescription { get; }

    internal ThreadAccessCheckResult(string name, string image_path, int thread_id, 
        string thread_description, int process_id, bool is_dead,
        int session_id, string command_line, AccessMask granted_access, string user,
        NtType type, SecurityDescriptor sd, TokenInformation token_info) 
        : base($"{name}/{process_id}.{thread_id}", 
            image_path, process_id, session_id, command_line, granted_access,
            true, is_dead, user, type, sd, token_info)
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
/// if one or more specified tokens can open them. If no tokens are specified then the 
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
    private static readonly NtType _process_type = NtType.GetTypeByType<NtProcess>();
    private static readonly NtType _thread_type = NtType.GetTypeByType<NtThread>();

    /// <summary>
    /// <para type="description">Specify what objects to check for.</para>
    /// </summary>
    [Parameter]
    public ProcessCheckMode CheckMode { get; set; }

    /// <summary>
    /// <para type="description">Specify specific access rights for threads.</para>
    /// </summary>
    [Parameter]
    [Alias("ThreadAccessRights")]
    public ThreadAccessRights ThreadAccess { get; set; }

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
        public string User { get; set; }
        public ProcessExtendedBasicInformationFlags ExtendedFlags { get; set; }
        public bool IsDeleting => ExtendedFlags.HasFlag(ProcessExtendedBasicInformationFlags.IsProcessDeleting);

        private ProcessDetails()
        {
        }

        public static ProcessDetails FromProcess(NtProcess process)
        {
            string name = process.Name;
            string image_path = process.FullPath;
            string command_line = "Unknown";
            string user = string.Empty;
            int process_id = -1;
            int session_id = 0;
            ProcessExtendedBasicInformationFlags flags = ProcessExtendedBasicInformationFlags.None;

            if (process.IsAccessGranted(ProcessAccessRights.QueryLimitedInformation))
            {
                command_line = process.CommandLine;
                process_id = process.ProcessId;
                session_id = process.SessionId;
                user = process.GetUser(false).GetResultOrDefault()?.ToString() ?? string.Empty;
                flags = process.ExtendedFlags;
            }
            else
            {
                using var dup_process = process.Duplicate(ProcessAccessRights.QueryLimitedInformation, AttributeFlags.None, DuplicateObjectOptions.None, false);
                if (dup_process.IsSuccess)
                {
                    command_line = dup_process.Result.CommandLine;
                    process_id = dup_process.Result.ProcessId;
                    session_id = dup_process.Result.SessionId;
                    user = dup_process.Result.GetUser(false).GetResultOrDefault()?.ToString() ?? string.Empty;
                    flags = dup_process.Result.ExtendedFlags;
                }
            }
            return new ProcessDetails() { Name = name, ImagePath = image_path,
                CommandLine = command_line, ProcessId = process_id, SessionId = session_id,
                User = user,
                ExtendedFlags = flags
            };
        }

        public static ProcessDetails FromThread(NtThread thread)
        {
            return new ProcessDetails()
            {
                Name = thread.ProcessName,
                ImagePath = string.Empty,
                CommandLine = string.Empty,
                ProcessId = thread.ProcessId,
                User = string.Empty
            };
        }
    }

    class ThreadDetails
    {
        public string Description { get; set; }
        public int ThreadId { get; set; }

        public static ThreadDetails FromThread(NtThread thread)
        {
            string description = string.Empty;
            int thread_id = -1;

            if (thread.IsAccessGranted(ThreadAccessRights.QueryLimitedInformation))
            {
                description = thread.Description;
                thread_id = thread.ThreadId;
            }
            else
            {
                using var dup_thread = thread.Duplicate(ThreadAccessRights.QueryLimitedInformation,
                    AttributeFlags.None, DuplicateObjectOptions.None, false);
                if (dup_thread.IsSuccess)
                {
                    description = dup_thread.Result.Description;
                    thread_id = dup_thread.Result.ThreadId;
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
       GenericMapping generic_mapping, SecurityDescriptor sd, TokenInformation token)
    {
        if (thread == null)
        {
            WriteObject(new ProcessAccessCheckResult(process.Name, process.ImagePath, process.ProcessId, process.SessionId, 
                process.CommandLine, granted_access, false, process.IsDeleting,
                process.User, _process_type, sd, token));
        }
        else
        {
            WriteObject(new ThreadAccessCheckResult(process.Name, process.ImagePath, thread.ThreadId, 
                thread.Description, process.ProcessId, process.IsDeleting, process.SessionId, process.CommandLine, granted_access,
                process.User, _thread_type, sd, token));
        }
    }

    private static AccessMask AdjustProcessAccess(AccessMask granted_access)
    {
        if (granted_access.IsAccessGranted(ProcessAccessRights.QueryInformation))
            granted_access |= ProcessAccessRights.QueryLimitedInformation;
        if (granted_access.IsAllAccessGranted(ProcessAccessRights.VmWrite | ProcessAccessRights.VmOperation))
            granted_access |= ProcessAccessRights.QueryLimitedInformation;
        if (granted_access.IsAccessGranted(ProcessAccessRights.SetInformation))
            granted_access |= ProcessAccessRights.SetLimitedInformation;
        return granted_access;
    }

    private static AccessMask AdjustThreadAccess(AccessMask granted_access)
    {
        if (granted_access.IsAccessGranted(ThreadAccessRights.QueryInformation))
            granted_access |= ThreadAccessRights.QueryLimitedInformation;
        if (granted_access.IsAccessGranted(ThreadAccessRights.SetInformation))
            granted_access |= ThreadAccessRights.SetLimitedInformation;
        if (granted_access.IsAccessGranted(ThreadAccessRights.SuspendResume))
            granted_access |= ThreadAccessRights.Resume;
        return granted_access;
    }

    private void CheckAccess(TokenEntry token, ProcessDetails process, ThreadDetails thread, NtType type, AccessMask access_rights, SecurityDescriptor sd)
    {
        AccessMask granted_access = NtSecurity.GetMaximumAccess(sd, token.Token, type.GenericMapping);
        granted_access = thread == null ? AdjustProcessAccess(granted_access) : AdjustThreadAccess(granted_access);
        if (IsAccessGranted(granted_access, access_rights))
        {
            WriteAccessCheckResult(process, thread, granted_access, type.GenericMapping, sd, token.Information);
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
        var sd = GetSecurityDescriptorReOpen(thread);
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
                using var new_thread = token.Token.RunUnderImpersonate(() => ReOpen(thread));
                if (new_thread.IsSuccess && IsAccessGranted(new_thread.Result.GrantedAccessMask, access_rights))
                {
                    WriteAccessCheckResult(proc_details, ThreadDetails.FromThread(thread), new_thread.Result.GrantedAccessMask,
                        _thread_type.GenericMapping, null, token.Information);
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
                var sd = GetSecurityDescriptorReOpen(process);
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
                        using var new_process = token.Token.RunUnderImpersonate(() => ReOpen(process));
                        if (new_process.IsSuccess && IsAccessGranted(new_process.Result.GrantedAccessMask, access_rights))
                        {
                            WriteAccessCheckResult(proc_details, null, new_process.Result.GrantedAccessMask,
                                _process_type.GenericMapping, null, token.Information);
                        }
                    }
                }
            }

            if (CheckThread())
            {
                using var new_process = process.ReOpen(ProcessAccessRights.QueryInformation, false);
                if (new_process.IsSuccess)
                {
                    using var threads = new_process.Result.GetThreads(ThreadAccessRights.QueryLimitedInformation).ToDisposableList();
                    foreach (var thread in threads)
                    {
                        DoAccessCheck(tokens, proc_details, thread, thread_access_rights);
                    }
                }
            }
        }
    }

    private protected override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
    {
        AccessMask access_rights = _process_type.MapGenericRights(Access);
        AccessMask thread_access_rights = _thread_type.MapGenericRights(ThreadAccess);
        if (!NtToken.EnableDebugPrivilege())
        {
            WriteWarning("Current process doesn't have SeDebugPrivilege, results may be inaccurate");
        }

        if (CheckProcess())
        {
            using var procs = NtProcess.GetProcesses(ProcessAccessRights.QueryLimitedInformation, false).ToDisposableList();
            DoAccessCheck(tokens, procs.Where(p => ShowDeadProcesses || !p.IsDeleting), access_rights, thread_access_rights);
        }
        else
        {
            using var threads = NtThread.GetThreads(ThreadAccessRights.QueryLimitedInformation, true).ToDisposableList();
            foreach (var thread in threads)
            {
                DoAccessCheck(tokens, ProcessDetails.FromThread(thread), thread, thread_access_rights);
            }
        }
    }

    private protected NtResult<O> ReOpen<O, X>(NtObjectWithDuplicate<O, X> obj) where O : NtObject where X : Enum
    {
        AccessMask mask = GenericAccessRights.MaximumAllowed;
        using (var o = obj.ReOpen(mask.ToSpecificAccess<X>(), false))
        {
            if (o.IsSuccess)
                return o.Map(x => (O)x.DuplicateObject());
        }

        AccessMask granted_mask = 0;
        AccessMask valid_access = obj.NtType.ValidAccess;
        uint test_mask = 1;
        while (test_mask < 0x00200000)
        {
            if (valid_access.IsAccessGranted(test_mask))
            {
                mask = test_mask;
                using var o = obj.ReOpen(mask.ToSpecificAccess<X>(), false);
                if (o.IsSuccess)
                    granted_mask |= test_mask;
            }

            test_mask <<= 1;
        }

        if (granted_mask.IsEmpty)
        {
            return NtResult<O>.CreateResultFromError(NtStatus.STATUS_ACCESS_DENIED, false);
        }
        return obj.ReOpen(granted_mask.ToSpecificAccess<X>(), false);
    }
}
