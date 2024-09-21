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
using NtCoreLib.Security.Authorization;
using NtObjectManager.Utils.ScheduledTask;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using TaskScheduler;

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// <para type="description">Access check result for a scheduled task.</para>
/// </summary>
public class ScheduledTaskAccessCheckResult : CommonAccessCheckResult
{
    /// <summary>
    /// Whether the task is enabled.
    /// </summary>
    public bool Enabled { get; }

    /// <summary>
    /// Whether the task is hidden.
    /// </summary>
    public bool Hidden { get; }

    /// <summary>
    /// Whether the task can be started on demand.
    /// </summary>
    public bool AllowDemandStart { get; }

    /// <summary>
    /// The full XML registration for the task.
    /// </summary>
    public string Xml { get; }

    /// <summary>
    /// The logon type of the task.
    /// </summary>
    public TaskLogonType LogonType { get; }

    /// <summary>
    /// The run level of the type.
    /// </summary>
    public TaskRunLevel RunLevel { get; }

    /// <summary>
    /// The principal of the type.
    /// </summary>
    public string Principal { get; }

    /// <summary>
    /// List of the actions.
    /// </summary>
    public IEnumerable<ScheduledTaskAction> Actions { get; }

    /// <summary>
    /// Number of actions.
    /// </summary>
    public int ActionCount { get; }

    /// <summary>
    /// The default type of action.
    /// </summary>
    public TaskActionType DefaultActionType => Actions.FirstOrDefault()?.ActionType ?? TaskActionType.None;

    /// <summary>
    /// The default action to be invoked.
    /// </summary>
    public string DefaultAction => Actions.FirstOrDefault()?.Action ?? string.Empty;

    /// <summary>
    /// Get the task name.
    /// </summary>
    public string TaskName => Path.GetFileName(Name);

    /// <summary>
    /// Get the task path.
    /// </summary>
    public string TaskPath => Path.GetDirectoryName(Name);

    /// <summary>
    /// Required privileged for task.
    /// </summary>
    public IEnumerable<string> RequiredPrivileges { get; }

    /// <summary>
    /// Process token SID.
    /// </summary>
    public TaskProcessTokenSid ProcessTokenSid { get; }

    /// <summary>
    /// Indicates whether the task has action arguments.
    /// </summary>
    public bool HasActionArguments { get; }

    /// <summary>
    /// Try and run the last with optional arguments.
    /// </summary>
    /// <param name="args">Optional arguments.</param>
    public void Run(params string[] args)
    {
        GetTask().Run(args);
    }

    /// <summary>
    /// Try and run the last with optional arguments.
    /// </summary>
    /// <param name="args">Optional arguments.</param>
    /// <param name="flags">Flags for the run operation.</param>
    /// <param name="session_id">Optional session ID (Needs UseSessionId flag).</param>
    /// <param name="user">Optional user name or SID.</param>
    public void RunEx(TaskRunFlags flags, int session_id, string user, params string[] args)
    {
        GetTask().RunEx(args, (int)flags, session_id, string.IsNullOrWhiteSpace(user) ? null : user);
    }

    internal ScheduledTaskAccessCheckResult(ScheduledTaskEntry entry, AccessMask granted_access,
        SecurityDescriptor sd, GenericMapping generic_mapping, TokenInformation token_info)
        : base(entry.Path, GetAccessibleScheduledTaskCmdlet.TypeName, granted_access,
            generic_mapping, sd,
            typeof(FileAccessRights), false, token_info)
    {
        Enabled = entry.Enabled;
        Hidden = entry.Hidden;
        AllowDemandStart = entry.AllowDemandStart;
        Xml = entry.Xml;
        LogonType = entry.LogonType;
        RunLevel = entry.RunLevel;
        Principal = entry.Principal;
        Actions = entry.Actions;
        ActionCount = Actions.Count();
        RequiredPrivileges = entry.RequiredPrivilege;
        ProcessTokenSid = entry.ProcessTokenSid;
        HasActionArguments = entry.HasActionArguments;
    }

    private IRegisteredTask GetTask()
    {
        ITaskService service = new TaskScheduler.TaskScheduler();
        service.Connect();

        ITaskFolder folder = service.GetFolder(Path.GetDirectoryName(Name));
        return folder.GetTask(Path.GetFileName(Name));
    }
}
