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
/// Debug event for the Create Process event.
/// </summary>
public sealed class CreateProcessDebugEvent : DebugEvent
{
    /// <summary>
    /// Subsystem key for the process.
    /// </summary>
    public int ProcessSubSystemKey { get; }
    /// <summary>
    /// Handle to the process file (if available).
    /// </summary>
    public NtFile File { get; }
    /// <summary>
    /// Base of image file.
    /// </summary>
    public long BaseOfImage { get; }
    /// <summary>
    /// Debug info file offset.
    /// </summary>
    public int DebugInfoFileOffset { get; }
    /// <summary>
    /// Debug info file size.
    /// </summary>
    public int DebugInfoSize { get; }
    /// <summary>
    /// Subsystem key for the thread.
    /// </summary>
    public int ThreadSubSystemKey { get; }
    /// <summary>
    /// Start address of the thread.
    /// </summary>
    public long ThreadStartAddress { get; }
    /// <summary>
    /// Handle to the process (if available).
    /// </summary>
    public NtProcess Process { get; }
    /// <summary>
    /// Handle to the thread (if available).
    /// </summary>
    public NtThread Thread { get; }

    internal CreateProcessDebugEvent(DbgUiWaitStatusChange debug_event, NtDebug debug)
        : base(debug_event, debug)
    {
        var info = debug_event.StateInfo.CreateProcess;
        Process = info.HandleToProcess == IntPtr.Zero ? null : NtProcess.FromHandle(info.HandleToProcess);
        Thread = info.HandleToThread == IntPtr.Zero ? null : NtThread.FromHandle(info.HandleToThread);
        var new_proc = info.NewProcess;
        ProcessSubSystemKey = new_proc.SubSystemKey;
        File = new_proc.FileHandle == IntPtr.Zero ? null : NtFile.FromHandle(new_proc.FileHandle);
        BaseOfImage = new_proc.BaseOfImage.ToInt64();
        DebugInfoFileOffset = new_proc.DebugInfoFileOffset;
        DebugInfoSize = new_proc.DebugInfoSize;
        var thread = new_proc.InitialThread;
        ThreadSubSystemKey = thread.SubSystemKey;
        ThreadStartAddress = thread.StartAddress.ToInt64();
    }

    /// <summary>
    /// Dispose the event.
    /// </summary>
    public override void Dispose()
    {
        Process?.Dispose();
        Thread?.Dispose();
        File?.Dispose();
    }
}
