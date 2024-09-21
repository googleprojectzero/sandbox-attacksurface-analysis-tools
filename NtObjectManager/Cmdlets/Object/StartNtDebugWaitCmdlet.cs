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
using NtCoreLib.Kernel.Debugger;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Wait for an event on a debug object.</para>
/// <para type="description">This cmdlet allows you to issue a wait for on a debug object. The timeout
/// value is a combination of all the allowed time parameters, e.g. if you specify 1 second and 1000 milliseconds it will
/// actually wait 2 seconds in total. Specifying -Infinite overrides the time parameters and will wait indefinitely.</para>
/// </summary>
/// <example>
///   <code>$ev = Start-NtDebugWait $dbg</code>
///   <para>Check for a debug event and return immediately.</para>
/// </example>
/// <example>
///   <code>$ev = Start-NtDebugWait $dbg -Seconds 10</code>
///   <para>Wait for 10 seconds for a debug event to be returned.</para>
/// </example>
/// <example>
///   <code>$ev = Start-NtDebugWait $dbg -Infinite</code>
///   <para>Wait indefinitely for a debug event to be returned.</para>
/// </example>
/// <example>
///   <code>$ev = Start-NtDebugWait $dbg -Infinite -Alterable</code>
///   <para>Wait indefinitely for a debug event to be returned in an alertable state.</para>
/// </example>
/// <example>
///   <code>$ev = Start-NtDebugWait $dbg -Infinite -ContinueEvent $ev</code>
///   <para>Continue a previous event with an explicit continue state for the event and wait indefinitely for a debug event to be returned.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsLifecycle.Start, "NtDebugWait", DefaultParameterSetName = "time")]
[OutputType(typeof(DebugEvent))]
public sealed class StartNtDebugWaitCmdlet : GetNtWaitTimeoutCmdlet
{
    private static DbgContinueStatus GetDbgContinueStatus(DebugEvent continue_event)
    {
        switch (continue_event.State)
        {
            case DbgState.BreakpointStateChange:
            case DbgState.ExceptionStateChange:
            case DbgState.SingleStepStateChange:
                return DbgContinueStatus.DBG_EXCEPTION_NOT_HANDLED;
            default:
                return DbgContinueStatus.DBG_CONTINUE;
        }
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    public StartNtDebugWaitCmdlet()
    {
    }

    /// <summary>
    /// <para type="description">Specify the debug object to wait on.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public NtDebug DebugObject { get; set; }

    /// <summary>
    /// <para type="description">Specify the wait should be alertable.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter Alertable { get; set; }

    /// <summary>
    /// <para type="description">Specify an event to continue before waiting.</para>
    /// </summary>
    [Parameter]
    public DebugEvent ContinueEvent { get; set; }

    /// <summary>
    /// <para type="description">If continue event specified then this is the status to use.</para>
    /// </summary>
    [Parameter]
    public DbgContinueStatus? ContinueStatus { get; set; }

    /// <summary>
    /// Overridden ProcessRecord method.
    /// </summary>
    protected override void ProcessRecord()
    {
        if (ContinueEvent != null)
        {
            DbgContinueStatus status = ContinueStatus ?? GetDbgContinueStatus(ContinueEvent);
            DebugObject.Continue(ContinueEvent.ProcessId, ContinueEvent.ThreadId, (NtStatus)status);
        }
        WriteObject(DebugObject.WaitForDebugEvent(Alertable, GetTimeout()));
    }
}
