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
using NtObjectManager.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using TaskScheduler;

namespace NtObjectManager.Cmdlets.Accessible
{
    /// <summary>
    /// The type of logon used for the task.
    /// </summary>
    public enum TaskLogonType
    {
        /// <summary>
        /// No logon type.
        /// </summary>
        None,
        /// <summary>
        /// Group activation.
        /// </summary>
        Group,
        /// <summary>
        /// User activation.
        /// </summary>
        User,
        /// <summary>
        /// Uses Services for User.
        /// </summary>
        S4U,
        /// <summary>
        /// Service account.
        /// </summary>
        ServiceAccount,
    }

    /// <summary>
    /// The task run level to use.
    /// </summary>
    public enum TaskRunLevel
    {
        /// <summary>
        /// Normal limited user.
        /// </summary>
        Limited,
        /// <summary>
        /// Highed run level available.
        /// </summary>
        Highest
    }

    /// <summary>
    /// The type of action the task performs when run.
    /// </summary>
    public enum TaskActionType
    {
        /// <summary>
        /// None or unknown.
        /// </summary>
        None,
        /// <summary>
        /// Execute a process.
        /// </summary>
        Execute,
        /// <summary>
        /// Load a COM object.
        /// </summary>
        ComObject,
        /// <summary>
        /// Send an email.
        /// </summary>
        SendEmail,
        /// <summary>
        /// Show a message.
        /// </summary>
        ShowMessage,
    }

    /// <summary>
    /// Flags for running a task.
    /// </summary>
    [Flags]
    public enum TaskRunFlags
    {
        /// <summary>
        /// None
        /// </summary>
        None = 0,
        /// <summary>
        /// Run as user calling Run.
        /// </summary>
        AsSelf = 1,
        /// <summary>
        /// Ignore task constraints.
        /// </summary>
        IgnoreConstrains = 2,
        /// <summary>
        /// Use the session ID for the terminal session.
        /// </summary>
        UseSessionId = 4,
        /// <summary>
        /// Run using a SID.
        /// </summary>
        UserSid = 8,
    }

    /// <summary>
    /// Class to represent a scheduled task action.
    /// </summary>
    public class ScheduledTaskAction
    {
        /// <summary>
        /// Type of action.
        /// </summary>
        public TaskActionType ActionType { get; }

        /// <summary>
        /// Summary of what will be invoked.
        /// </summary>
        public string Action { get; }

        /// <summary>
        /// Overridden ToString.
        /// </summary>
        /// <returns>The action as a string.</returns>
        public override string ToString()
        {
            return $"{ActionType}: {Action}";
        }

        internal ScheduledTaskAction(IAction action)
        {
            Action = string.Empty;
            switch (action.Type)
            {
                case _TASK_ACTION_TYPE.TASK_ACTION_EXEC:
                    ActionType = TaskActionType.Execute;
                    if (action is IExecAction exec_action)
                    {
                        Action = $"{exec_action.Path} {exec_action.Arguments}";
                    }
                    break;
                case _TASK_ACTION_TYPE.TASK_ACTION_COM_HANDLER:
                    ActionType = TaskActionType.ComObject;
                    if (action is IComHandlerAction com_action)
                    {
                        Action = com_action.ClassId;
                    }
                    break;
                case _TASK_ACTION_TYPE.TASK_ACTION_SEND_EMAIL:
                    ActionType = TaskActionType.SendEmail;
                    if (action is IEmailAction email_action)
                    {
                        Action = $"From: {email_action.From} To: {email_action.To}";
                    }
                    break;
                case _TASK_ACTION_TYPE.TASK_ACTION_SHOW_MESSAGE:
                    ActionType = TaskActionType.ShowMessage;
                    if (action is IShowMessageAction msg_action)
                    {
                        Action = $"Title: {msg_action.Title} Body: {msg_action.MessageBody}";
                    }
                    break;
            }
        }
    }

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

        internal ScheduledTaskAccessCheckResult(GetAccessibleScheduledTaskCmdlet.TaskSchedulerEntry entry, AccessMask granted_access,
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
        }

        private IRegisteredTask GetTask()
        {
            ITaskService service = new TaskScheduler.TaskScheduler();
            service.Connect();

            ITaskFolder folder = service.GetFolder(Path.GetDirectoryName(Name));
            return folder.GetTask(Path.GetFileName(Name));
        }
    }

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
    public class GetAccessibleScheduledTaskCmdlet : CommonAccessBaseWithAccessCmdlet<FileAccessRights>
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
                string sddl = entry.SecurityDescriptor;

                if (string.IsNullOrWhiteSpace(sddl) || string.IsNullOrWhiteSpace(path))
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
                        WriteObject(entry.CreateResult(granted_access, token.Information));
                    }
                }
            }
        }

        internal class TaskSchedulerEntry
        {
            public string Path { get; }
            public bool Folder { get; }
            public string SecurityDescriptor { get; }
            public bool Enabled { get; }
            public bool Hidden { get; }
            public bool AllowDemandStart { get; }
            public string Xml { get; }
            public TaskLogonType LogonType { get; }
            public TaskRunLevel RunLevel { get; }
            public string Principal { get; }
            public IEnumerable<ScheduledTaskAction> Actions { get; }

            public TaskSchedulerEntry(IRegisteredTask task)
            {
                SecurityDescriptor = task.GetSecurityDescriptor((int)SecurityInformation.AllBasic);
                Path = task.Path;
                Enabled = task.Enabled;
                Xml = task.Xml;
                var definition = task.Definition;
                var settings = definition.Settings;
                Hidden = settings.Hidden;
                AllowDemandStart = settings.AllowDemandStart;
                var principal = definition.Principal;
                if (principal.RunLevel == _TASK_RUNLEVEL.TASK_RUNLEVEL_HIGHEST)
                {
                    RunLevel = TaskRunLevel.Highest;
                }

                TaskLogonType logon_type = TaskLogonType.None;
                string principal_name = string.Empty;
                switch (principal.LogonType)
                {
                    case _TASK_LOGON_TYPE.TASK_LOGON_GROUP:
                        logon_type = TaskLogonType.Group;
                        principal_name = principal.GroupId;
                        break;
                    case _TASK_LOGON_TYPE.TASK_LOGON_INTERACTIVE_TOKEN:
                    case _TASK_LOGON_TYPE.TASK_LOGON_PASSWORD:
                    case _TASK_LOGON_TYPE.TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD:
                        logon_type = TaskLogonType.User;
                        principal_name = principal.UserId;
                        break;
                    case _TASK_LOGON_TYPE.TASK_LOGON_SERVICE_ACCOUNT:
                        logon_type = TaskLogonType.ServiceAccount;
                        principal_name = principal.UserId;
                        break;
                    case _TASK_LOGON_TYPE.TASK_LOGON_S4U:
                        logon_type = TaskLogonType.S4U;
                        principal_name = principal.UserId;
                        break;
                }
                LogonType = logon_type;
                Principal = principal_name;
                Actions = definition.Actions.Cast<IAction>().Select(a => new ScheduledTaskAction(a)).ToList().AsReadOnly();
            }

            public TaskSchedulerEntry(ITaskFolder folder)
            {
                Folder = true;
                SecurityDescriptor = folder.GetSecurityDescriptor((int)SecurityInformation.AllBasic);
                Path = folder.Path;
            }

            public CommonAccessCheckResult CreateResult(AccessMask granted_access, TokenInformation token_info)
            {
                if (Folder)
                {
                    return new CommonAccessCheckResult(Path, "Scheduled Task", granted_access, _file_type.GenericMapping,
                        new SecurityDescriptor(SecurityDescriptor), typeof(FileDirectoryAccessRights), true, token_info);
                }
                else
                {
                    return new ScheduledTaskAccessCheckResult(this, granted_access, new SecurityDescriptor(SecurityDescriptor), 
                        _file_type.GenericMapping, token_info);
                }
            }
        }

        #endregion

        #region Private Members
        private static readonly NtType _file_type = NtType.GetTypeByType<NtFile>();

        private IEnumerable<TaskSchedulerEntry> EnumEntries(ITaskFolder folder)
        {
            if (CheckMode == TaskCheckMode.FoldersOnly || CheckMode == TaskCheckMode.All)
            {
                yield return new TaskSchedulerEntry(folder);
            }

            if (CheckMode == TaskCheckMode.TasksOnly || CheckMode == TaskCheckMode.All)
            {
                foreach (IRegisteredTask task in folder.GetTasks((int)_TASK_ENUM_FLAGS.TASK_ENUM_HIDDEN))
                {
                    yield return new TaskSchedulerEntry(task);
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

        private IEnumerable<TaskSchedulerEntry> GetTaskSchedulerEntries()
        {
            ITaskService service = new TaskScheduler.TaskScheduler();
            service.Connect();

            ITaskFolder folder = service.GetFolder(@"\");
            return EnumEntries(folder);
        }
        #endregion
    }
}
