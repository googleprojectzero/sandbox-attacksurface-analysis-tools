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

using TaskScheduler;

namespace NtObjectManager.Utils.ScheduledTask;

/// <summary>
/// Class to represent a scheduled task action.
/// </summary>
public class ScheduledTaskAction
{
    /// <summary>
    /// The ID of the action.
    /// </summary>
    public string Id { get; }

    /// <summary>
    /// Type of action.
    /// </summary>
    public TaskActionType ActionType { get; }

    /// <summary>
    /// Summary of what will be invoked.
    /// </summary>
    public string Action { get; }

    /// <summary>
    /// Indicates if this action takes arguments.
    /// </summary>
    public bool HasArguments { get; }

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
        Id = action.Id ?? string.Empty;
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
                    Action = $"{com_action.ClassId:B} {com_action.Data}";
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
        HasArguments = Action?.Contains("$(Arg") ?? false;
    }
}
