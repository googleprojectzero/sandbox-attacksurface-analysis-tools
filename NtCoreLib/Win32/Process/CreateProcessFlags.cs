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

using System;

namespace NtCoreLib.Win32.Process;

/// <summary>
/// Flags for create process.
/// </summary>
[Flags]
public enum CreateProcessFlags : uint
{
    /// <summary>
    /// No flags.
    /// </summary>
    None = 0,
    /// <summary>
    /// Debug process.
    /// </summary>
    DebugProcess = 0x00000001,
    /// <summary>
    /// Debug only this process.
    /// </summary>
    DebugOnlyThisProcess = 0x00000002,
    /// <summary>
    /// Create suspended.
    /// </summary>
    Suspended = 0x00000004,
    /// <summary>
    /// Detach process.
    /// </summary>
    DetachedProcess = 0x00000008,
    /// <summary>
    /// Create a new console.
    /// </summary>
    NewConsole = 0x00000010,
    /// <summary>
    /// Normal priority class.
    /// </summary>
    NormalPriorityClass = 0x00000020,
    /// <summary>
    /// Idle priority class.
    /// </summary>
    IdlePriorityClass = 0x00000040,
    /// <summary>
    /// High priority class.
    /// </summary>
    HighPriorityClass = 0x00000080,
    /// <summary>
    /// Realtime priority class.
    /// </summary>
    RealtimePriorityClass = 0x00000100,
    /// <summary>
    /// Create a new process group.
    /// </summary>
    NewProcessGroup = 0x00000200,
    /// <summary>
    /// Create from a unicode environment.
    /// </summary>
    UnicodeEnvironment = 0x00000400,
    /// <summary>
    /// Create a separate WOW VDM.
    /// </summary>
    SeparateWowVdm = 0x00000800,
    /// <summary>
    /// Share the WOW VDM.
    /// </summary>
    SharedWowVdm = 0x00001000,
    /// <summary>
    /// Force DOS process.
    /// </summary>
    ForceDOS = 0x00002000,
    /// <summary>
    /// Below normal priority class.
    /// </summary>
    BelowNormalPriorityClass = 0x00004000,
    /// <summary>
    /// Above normal priority class.
    /// </summary>
    AboveNormalPriorityClass = 0x00008000,
    /// <summary>
    /// Inherit parent affinity.
    /// </summary>
    InheritParentAffinity = 0x00010000,
    /// <summary>
    /// Inherit caller priority (deprecated)
    /// </summary>
    InheritCallerPriority = 0x00020000,
    /// <summary>
    /// Create a protected process.
    /// </summary>
    ProtectedProcess = 0x00040000,
    /// <summary>
    /// Specify extended startup information is present.
    /// </summary>
    ExtendedStartupInfoPresent = 0x00080000,
    /// <summary>
    /// Process mode background begin.
    /// </summary>
    ModeBackgroundBegin = 0x00100000,
    /// <summary>
    /// Process mode background end.
    /// </summary>
    ModeBackgroundEnd = 0x00200000,
    /// <summary>
    /// Create a secure process.
    /// </summary>
    SecureProcess = 0x00400000,
    /// <summary>
    /// Breakaway from a job object.
    /// </summary>
    BreakawayFromJob = 0x01000000,
    /// <summary>
    /// Preserve code authz level.
    /// </summary>
    PreserveCodeAuthZLevel = 0x02000000,
    /// <summary>
    /// Default error mode.
    /// </summary>
    DefaultErrorMode = 0x04000000,
    /// <summary>
    /// No window.
    /// </summary>
    NoWindow = 0x08000000,
    /// <summary>
    /// Profile user.
    /// </summary>
    ProfileUser = 0x10000000,
    /// <summary>
    /// Profile kernel.
    /// </summary>
    ProfileKernel = 0x20000000,
    /// <summary>
    /// Profile server.
    /// </summary>
    ProfileServer = 0x40000000,
    /// <summary>
    /// Ignore system default.
    /// </summary>
    IgnoreSystemDefault = 0x80000000
}
#pragma warning restore

