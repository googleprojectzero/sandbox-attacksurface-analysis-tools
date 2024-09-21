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

using TaskScheduler;

namespace NtObjectManager.Utils.ScheduledTask;

/// <summary>
/// Type of scheduled task trigger.
/// </summary>
public enum ScheduledTaskTriggerType
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    Event = 0,
    Time = 1,
    Daily = 2,
    Weekly = 3,
    Monthly = 4,
    MouthlyDayOfWeek = 5,
    Idle = 6,
    Registration = 7,
    Boot = 8,
    Logon = 9,
    SessionStateChange = 11,
    WNF = 12,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}

/// <summary>
/// Class for a scheduled task trigger.
/// </summary>
public class ScheduledTaskTrigger
{
    /// <summary>
    /// The ID of the trigger.
    /// </summary>
    public string Id { get; }

    /// <summary>
    /// The type of the trigger.
    /// </summary>
    public ScheduledTaskTriggerType TriggerType { get; }

    /// <summary>
    /// The start boundary for the trigger.
    /// </summary>
    public string StartBoundary { get; }

    /// <summary>
    /// The end boundary for the trigger.
    /// </summary>
    public string EndBoundary { get; }

    /// <summary>
    /// Time limit for execution.
    /// </summary>
    public string ExecutionTimeLimit { get; }

    internal static ScheduledTaskTrigger Create(ITrigger trigger)
    {
        return new ScheduledTaskTrigger(trigger);
    }

    private protected ScheduledTaskTrigger(ITrigger trigger)
    {
        Id = trigger.Id;
        TriggerType = (ScheduledTaskTriggerType)(int)trigger.Type;
        StartBoundary = trigger.StartBoundary;
        EndBoundary = trigger.EndBoundary;
        ExecutionTimeLimit = trigger.ExecutionTimeLimit;
    }
}
