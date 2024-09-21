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

using NtCoreLib;
using NtCoreLib.Security;
using NtCoreLib.Security.Authorization;
using NtObjectManager.Utils.ScheduledTask;
using System.Collections.Generic;
using System.Management.Automation;
using TaskScheduler;

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// <para type="description">Limit access check to specific types of task information.</para>
/// </summary>
public enum TaskCheckMode
{
    /// <summary>
    /// Check tasks only.
    /// </summary>
    TasksOnly,
    /// <summary>
    /// Check folders only.
    /// </summary>
    FoldersOnly,
    /// <summary>
    /// Check both folders and tasks.
    /// </summary>
    All,
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
///   <code>Get-AccessibleScheduledTask -Executable</code>
///   <para>Check all executable scheduled tasks for the current process token.</para>
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
public partial class GetAccessibleScheduledTaskCmdlet : CommonAccessBaseWithAccessCmdlet<FileAccessRights>
{
    #region Public Properties

    /// <summary>
    /// <para type="description">Limit access check to specific types of files.</para>
    /// </summary>
    [Parameter]
    public TaskCheckMode CheckMode { get; set; }

    /// <summary>
    /// <para type="description">Specify a set of directory access rights which a folder must at least be accessible for to count as an access.</para>
    /// </summary>
    [Parameter]
    [Alias("DirectoryAccessRights")]
    public FileDirectoryAccessRights DirectoryAccess { get; set; }

    /// <summary>
    /// <para type="description">Shortcut to specify that we're querying for executable tasks.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter Executable { get; set; }

    /// <summary>
    /// <para type="description">Shortcut to specify that we're querying for writable tasks or directories.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter Writable { get; set; }

    #endregion

    #region Internal Members
    internal const string TypeName = "Scheduled Task";

    private protected override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
    {
        foreach (var entry in GetTaskSchedulerEntries())
        {
            string path = entry.Path;
            if (entry.SecurityDescriptor == null)
            {
                continue;
            }

            AccessMask requested_access;
            if (entry.Folder)
            {
                requested_access = Writable ? FileDirectoryAccessRights.AddSubDirectory : DirectoryAccess;
            }
            else
            {
                requested_access = Executable ? FileAccessRights.ReadData | FileAccessRights.Execute : 0;
                if (Writable)
                {
                    requested_access |= FileAccessRights.WriteData;
                }

                if (requested_access.IsEmpty)
                {
                    requested_access = Access;
                }
            }

            AccessMask access_rights = _file_type.GenericMapping.MapMask(requested_access);
            foreach (TokenEntry token in tokens)
            {
                SecurityDescriptor sd = entry.SecurityDescriptor.Clone();
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
                    WriteObject(entry.CreateResult(granted_access, token.Information));
                }
            }
        }
    }

    #endregion

    #region Private Members
    private static readonly NtType _file_type = NtType.GetTypeByType<NtFile>();

    private IEnumerable<ScheduledTaskEntry> EnumEntries(ITaskFolder folder)
    {
        if (CheckMode == TaskCheckMode.FoldersOnly || CheckMode == TaskCheckMode.All)
        {
            yield return new ScheduledTaskEntry(folder);
        }

        if (CheckMode == TaskCheckMode.TasksOnly || CheckMode == TaskCheckMode.All)
        {
            foreach (IRegisteredTask task in folder.GetTasks((int)_TASK_ENUM_FLAGS.TASK_ENUM_HIDDEN))
            {
                yield return new ScheduledTaskEntry(task);
            }
        }

        foreach (ITaskFolder sub_folder in folder.GetFolders(0))
        {
            foreach (var entry in EnumEntries(sub_folder))
            {
                yield return entry;
            }
        }
    }

    private IEnumerable<ScheduledTaskEntry> GetTaskSchedulerEntries()
    {
        ITaskService service = new TaskScheduler.TaskScheduler();
        service.Connect();

        ITaskFolder folder = service.GetFolder(@"\");
        return EnumEntries(folder);
    }
    #endregion
}
