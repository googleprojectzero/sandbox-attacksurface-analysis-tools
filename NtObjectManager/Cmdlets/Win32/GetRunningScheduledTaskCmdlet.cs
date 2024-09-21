//  Copyright 2020 Google Inc. All Rights Reserved.
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

using NtObjectManager.Utils.ScheduledTask;
using System.IO;
using System.Linq;
using System.Management.Automation;
using TaskScheduler;

namespace NtObjectManager.Cmdlets.Win32;

/// <summary>
/// <para type="synopsis">Get a list of running scheduled tasks.</para>
/// <para type="description">This cmdlet enumerates all running scheduled tasks.</para>
/// </summary>
/// <remarks>For best results this command should be run as an administrator.</remarks>
/// <example>
///   <code>Get-RunningScheduledTask</code>
///   <para>Get all running scheduled tasks.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "RunningScheduledTask")]
[OutputType(typeof(RunningScheduledTaskEntry))]
public class GetRunningScheduledTaskCmdlet : PSCmdlet
{
    /// <summary>
    /// Process record.
    /// </summary>
    protected override void ProcessRecord()
    {
        ITaskService service = new TaskScheduler.TaskScheduler();
        service.Connect();
        foreach (var running_task in service.GetRunningTasks((int)_TASK_ENUM_FLAGS.TASK_ENUM_HIDDEN).Cast<IRunningTask>())
        {
            try
            {
                ITaskFolder folder = service.GetFolder(Path.GetDirectoryName(running_task.Path));
                IRegisteredTask task = folder.GetTask(running_task.Name);
                WriteObject(new RunningScheduledTaskEntry(running_task, task));
            }
            catch
            {
            }
        }
    }
}
