//  Copyright 2018 Google Inc. All Rights Reserved.
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

using NtCoreLib.Utilities.Reflection;
using System;

namespace NtCoreLib.Win32.Tracing;

[Flags]
internal enum LogFileModeFlags : uint
{
    [SDKName("EVENT_TRACE_FILE_MODE_NONE")]
    None = 0,
    [SDKName("EVENT_TRACE_FILE_MODE_SEQUENTIAL")]
    Sequential = 0x00000001,
    [SDKName("EVENT_TRACE_FILE_MODE_CIRCULAR")]
    Circular = 0x00000002,
    [SDKName("EVENT_TRACE_FILE_MODE_APPEND")]
    Append = 0x00000004,
    [SDKName("EVENT_TRACE_FILE_MODE_NEWFILE")]
    NewFile = 0x00000008,
    [SDKName("EVENT_TRACE_FILE_MODE_PREALLOCATE")]
    Preallocate = 0x00000020,
    [SDKName("EVENT_TRACE_NONSTOPPABLE_MODE")]
    NonStoppable = 0x00000040,
    [SDKName("EVENT_TRACE_SECURE_MODE")]
    Secure = 0x00000080,
    [SDKName("EVENT_TRACE_REAL_TIME_MODE")]
    RealTime = 0x00000100,
    [SDKName("EVENT_TRACE_DELAY_OPEN_FILE_MODE")]
    DelayOpen = 0x00000200,
    [SDKName("EVENT_TRACE_BUFFERING_MODE")]
    Buffering = 0x00000400,
    [SDKName("EVENT_TRACE_PRIVATE_LOGGER_MODE")]
    PrivateLogger = 0x00000800,
    [SDKName("EVENT_TRACE_ADD_HEADER_MODE")]
    AddHeader = 0x00001000,
    [SDKName("EVENT_TRACE_USE_KBYTES_FOR_SIZE")]
    UseKBytesForSize = 0x00002000,
    [SDKName("EVENT_TRACE_USE_GLOBAL_SEQUENCE")]
    UseGlobalSequence = 0x00004000,
    [SDKName("EVENT_TRACE_USE_LOCAL_SEQUENCE")]
    UseLocalSequence = 0x00008000,
    [SDKName("EVENT_TRACE_RELOG_MODE")]
    Relog = 0x00010000,
    [SDKName("EVENT_TRACE_PRIVATE_IN_PROC")]
    PrivateInProc = 0x00020000,
    [SDKName("EVENT_TRACE_MODE_RESERVED")]
    Reserved = 0x00100000,
    [SDKName("EVENT_TRACE_USE_PAGED_MEMORY")]
    UsePagedMember = 0x01000000,
    [SDKName("EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING")]
    NoPerProcessorBuffering = 0x10000000,
    [SDKName("EVENT_TRACE_SYSTEM_LOGGER_MODE")]
    SystemLogger = 0x02000000,
    [SDKName("EVENT_TRACE_ADDTO_TRIAGE_DUMP")]
    AddToTriageDump = 0x80000000,
    [SDKName("EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN")]
    StopOnHybridShutdown = 0x00400000,
    [SDKName("EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN")]
    PersistOnHybridShutdown = 0x00800000,
    [SDKName("EVENT_TRACE_INDEPENDENT_SESSION_MODE")]
    IndependentSession = 0x08000000,
    [SDKName("EVENT_TRACE_COMPRESSED_MODE")]
    Compressed = 0x04000000,
}
#pragma warning restore 1591
