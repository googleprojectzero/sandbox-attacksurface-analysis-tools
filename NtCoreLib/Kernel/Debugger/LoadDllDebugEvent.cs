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
/// Debug event for load DLL event.
/// </summary>
public sealed class LoadDllDebugEvent : DebugEvent
{
    /// <summary>
    /// DLL file handle.
    /// </summary>
    public NtFile File { get; }
    /// <summary>
    /// Base of loaded DLL.
    /// </summary>
    public long BaseOfDll { get; }
    /// <summary>
    /// Debug info offset.
    /// </summary>
    public int DebugInfoFileOffset { get; }
    /// <summary>
    /// Debug info size.
    /// </summary>
    public int DebugInfoSize { get; }
    /// <summary>
    /// Address of name.
    /// </summary>
    public long NamePointer { get; }

    internal LoadDllDebugEvent(DbgUiWaitStatusChange debug_event, NtDebug debug)
            : base(debug_event, debug)
    {
        var info = debug_event.StateInfo.LoadDll;
        File = info.FileHandle == IntPtr.Zero ? null : NtFile.FromHandle(info.FileHandle);
        BaseOfDll = info.BaseOfDll.ToInt64();
        DebugInfoFileOffset = info.DebugInfoFileOffset;
        DebugInfoSize = info.DebugInfoSize;
        NamePointer = info.NamePointer.ToInt64();
    }

    /// <summary>
    /// Dispose the event.
    /// </summary>
    public override void Dispose()
    {
        File?.Dispose();
    }
}
