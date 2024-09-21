//  Copyright 2016 Google Inc. All Rights Reserved.
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

using NtCoreLib.Native.SafeHandles;
using NtCoreLib.Win32.Process.Interop;
using System;

namespace NtCoreLib.Win32.Process;

/// <summary>
/// Class representing a win32 process.
/// </summary>
public sealed class Win32Process : IDisposable
{
    /// <summary>
    /// Dispose the process.
    /// </summary>
    public void Dispose()
    {
        if (TerminateOnDispose)
        {
            Process?.Terminate(NtStatus.STATUS_PROCESS_IS_TERMINATING, false);
        }
        Process?.Dispose();
        Thread?.Dispose();
    }

    /// <summary>
    /// Resume the entire process.
    /// </summary>
    public void Resume()
    {
        Process?.Resume();
    }

    /// <summary>
    /// Suspend the entire process.
    /// </summary>
    public void Suspend()
    {
        Process?.Suspend();
    }

    /// <summary>
    /// Terminate the process
    /// </summary>
    /// <param name="exitcode">The exit code for the termination</param>
    public void Terminate(NtStatus exitcode)
    {
        Process?.Terminate(exitcode);
    }

    #region Public Properties
    /// <summary>
    /// The handle to the process.
    /// </summary>
    public NtProcess Process { get; }
    /// <summary>
    /// The handle to the initial thread.
    /// </summary>
    public NtThread Thread { get; }
    /// <summary>
    /// The process ID of the process.
    /// </summary>
    public int Pid { get; }
    /// <summary>
    /// The thread ID of the initial thread.
    /// </summary>
    public int Tid { get; }
    /// <summary>
    /// True to terminate process when disposed.
    /// </summary>
    public bool TerminateOnDispose { get; set; }
    /// <summary>
    /// Get the process' exit status.
    /// </summary>
    public int ExitStatus => Process.ExitStatus;
    /// <summary>
    /// Get the process' exit status as an NtStatus code.
    /// </summary>
    public NtStatus ExitNtStatus => Process.ExitNtStatus;
    #endregion

    #region Public Operators
    /// <summary>
    /// Explicit conversion operator to an NtThread object.
    /// </summary>
    /// <param name="process">The win32 process</param>
    public static explicit operator NtThread(Win32Process process) => process.Thread;

    /// <summary>
    /// Explicit conversion operator to an NtProcess object.
    /// </summary>
    /// <param name="process">The win32 process</param>
    public static explicit operator NtProcess(Win32Process process) => process.Process;
    #endregion

    #region Constructors
    internal Win32Process(PROCESS_INFORMATION proc_info, bool terminate_on_dispose)
    {
        Process = NtProcess.FromHandle(new SafeKernelObjectHandle(proc_info.hProcess, true));
        Thread = NtThread.FromHandle(new SafeKernelObjectHandle(proc_info.hThread, true));
        Pid = proc_info.dwProcessId;
        Tid = proc_info.dwThreadId;
        TerminateOnDispose = terminate_on_dispose;
    }
    #endregion
}
