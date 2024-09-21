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

using System;

namespace NtCoreLib.Kernel.Debugger;

/// <summary>
/// The base class for a debug event.
/// </summary>
public abstract class DebugEvent : IDisposable
{
    #region Private Members
    private readonly NtDebug _debug;
    #endregion

    /// <summary>
    /// Process ID for the event.
    /// </summary>
    public int ProcessId { get; }

    /// <summary>
    /// Thread ID for the event.
    /// </summary>
    public int ThreadId { get; }

    /// <summary>
    /// The event code.
    /// </summary>
    public DbgState State { get; }

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="debug_event">The current debug event.</param>
    /// <param name="debug">The debug port associated with this event.</param>
    protected DebugEvent(DbgUiWaitStatusChange debug_event, NtDebug debug)
    {
        ProcessId = debug_event.AppClientId.UniqueProcess.ToInt32();
        ThreadId = debug_event.AppClientId.UniqueThread.ToInt32();
        State = debug_event.NewState;
        _debug = debug;
    }

    /// <summary>
    /// Continue the debugged process.
    /// </summary>
    /// <param name="continue_status">The continue status code.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public NtStatus Continue(NtStatus continue_status, bool throw_on_error)
    {
        return _debug.Continue(ProcessId, ThreadId, continue_status, throw_on_error);
    }

    /// <summary>
    /// Continue the debugged process.
    /// </summary>
    /// <param name="continue_status">The continue status code.</param>
    public void Continue(NtStatus continue_status)
    {
        _debug.Continue(ProcessId, ThreadId, continue_status);
    }

    /// <summary>
    /// Continue the debugged process with a success code.
    /// </summary>
    public void Continue()
    {
        Continue(NtStatus.DBG_CONTINUE);
    }

    /// <summary>
    /// Dispose the event.
    /// </summary>
    public virtual void Dispose()
    {
    }

    internal static DebugEvent FromDebugEvent(DbgUiWaitStatusChange debug_event, NtDebug debug)
    {
        return debug_event.NewState switch
        {
            DbgState.CreateProcessStateChange => new CreateProcessDebugEvent(debug_event, debug),
            DbgState.CreateThreadStateChange => new CreateThreadDebugEvent(debug_event, debug),
            DbgState.BreakpointStateChange or DbgState.ExceptionStateChange or DbgState.SingleStepStateChange => new ExceptionDebugEvent(debug_event, debug),
            DbgState.ExitProcessStateChange => new ExitProcessDebugEvent(debug_event, debug),
            DbgState.ExitThreadStateChange => new ExitThreadDebugEvent(debug_event, debug),
            DbgState.LoadDllStateChange => new LoadDllDebugEvent(debug_event, debug),
            DbgState.UnloadDllStateChange => new UnloadDllDebugEvent(debug_event, debug),
            _ => new UnknownDebugEvent(debug_event, debug),
        };
    }
}
