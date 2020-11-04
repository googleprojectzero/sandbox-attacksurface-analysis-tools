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
using NtObjectManager.Cmdlets.Accessible;
using System;
using System.Collections.Generic;
using System.Linq;
using TaskScheduler;

namespace NtObjectManager.Utils.ScheduledTask
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
    /// Task process token SID type.
    /// </summary>
    public enum TaskProcessTokenSid
    {
        /// <summary>
        /// None.
        /// </summary>
        None = 0,
        /// <summary>
        /// Unrestricted task SID.
        /// </summary>
        Unrestricted = 1,
        /// <summary>
        /// Default task SID.
        /// </summary>
        Default = 2
    }

    /// <summary>
    /// Schedled task entry.
    /// </summary>
    public class ScheduledTaskEntry
    {
        /// <summary>
        /// The path to the scheduled task.
        /// </summary>
        public string Path { get; }
        /// <summary>
        /// Is this entry a folder.
        /// </summary>
        public bool Folder { get; }
        /// <summary>
        /// The scheduled task security descriptor.
        /// </summary>
        public SecurityDescriptor SecurityDescriptor { get; }
        /// <summary>
        /// Is the task enabled.
        /// </summary>
        public bool Enabled { get; }
        /// <summary>
        /// Is the task hidden.
        /// </summary>
        public bool Hidden { get; }
        /// <summary>
        /// Can the task be run on demand.
        /// </summary>
        public bool AllowDemandStart { get; }
        /// <summary>
        /// The XML task file.
        /// </summary>
        public string Xml { get; }
        /// <summary>
        /// Principal logon type.
        /// </summary>
        public TaskLogonType LogonType { get; }
        /// <summary>
        /// Principal run level.
        /// </summary>
        public TaskRunLevel RunLevel { get; }
        /// <summary>
        /// Principal name.
        /// </summary>
        public string Principal { get; }
        /// <summary>
        /// Actions for the task.
        /// </summary>
        public IEnumerable<ScheduledTaskAction> Actions { get; }
        /// <summary>
        /// List of required privileges.
        /// </summary>
        public IEnumerable<string> RequiredPrivilege { get; }
        /// <summary>
        /// Principal process token SID.
        /// </summary>
        public TaskProcessTokenSid ProcessTokenSid { get; }
        /// <summary>
        /// Triggers for the task.
        /// </summary>
        public IEnumerable<ScheduledTaskTrigger> Triggers { get; }
        /// <summary>
        /// Indicates whether the task has action arguments.
        /// </summary>
        public bool HasActionArguments { get; }

        internal ScheduledTaskEntry(IRegisteredTask task)
        {
            SecurityDescriptor = SecurityDescriptor.Parse(task.GetSecurityDescriptor((int)SecurityInformation.AllBasic), false).GetResultOrDefault();
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

            List<string> privs = new List<string>();
            if (principal is IPrincipal2 prin2)
            {
                privs.AddRange(Enumerable.Range(0, prin2.RequiredPrivilegeCount).Select(i => prin2.RequiredPrivilege[i]));
                ProcessTokenSid = (TaskProcessTokenSid)(int)prin2.ProcessTokenSidType;
            }
            RequiredPrivilege = privs.AsReadOnly();

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
            HasActionArguments = Actions.Any(a => a.HasArguments);
            Triggers = definition.Triggers.Cast<ITrigger>().Select(ScheduledTaskTrigger.Create).ToList().AsReadOnly();
        }

        internal ScheduledTaskEntry(ITaskFolder folder)
        {
            Folder = true;
            SecurityDescriptor = SecurityDescriptor.Parse(folder.GetSecurityDescriptor((int)SecurityInformation.AllBasic), false).GetResultOrDefault();
            Path = folder.Path;
        }

        internal CommonAccessCheckResult CreateResult(AccessMask granted_access, TokenInformation token_info)
        {
            if (Folder)
            {
                return new CommonAccessCheckResult(Path, "Scheduled Task", granted_access, _file_type.GenericMapping,
                    SecurityDescriptor.Clone(), typeof(FileDirectoryAccessRights), true, token_info);
            }
            else
            {
                return new ScheduledTaskAccessCheckResult(this, granted_access, SecurityDescriptor.Clone(),
                    _file_type.GenericMapping, token_info);
            }
        }

        private static readonly NtType _file_type = NtType.GetTypeByType<NtFile>();
    }
}
