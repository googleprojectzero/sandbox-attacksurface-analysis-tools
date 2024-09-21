//  Copyright 2023 Google LLC. All Rights Reserved.
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

namespace NtCoreLib.Win32.IO;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
[Flags]
public enum CreateFileFlagsAndAttributes : uint
{
    None = 0,
    ReadOnly = 0x00000001,
    Hidden = 0x00000002,
    System = 0x00000004,
    Directory = 0x00000010,
    Archive = 0x00000020,
    Device = 0x00000040,
    Normal = 0x00000080,
    Temporary = 0x00000100,
    SparseFile = 0x00000200,
    ReparsePoint = 0x00000400,
    Compressed = 0x00000800,
    Offline = 0x00001000,
    NotContentIndexed = 0x00002000,
    Encrypted = 0x00004000,
    IntegrityStream = 0x00008000,
    SecurityIdentification = 0x00010000,
    SecurityImpersonation = 0x00020000,
    SecurityDelegation = 0x00030000,
    ContextTracking = 0x00040000,
    EffectiveOnly = 0x00080000,
    SQoSPresent = 0x00100000,
    OpenReparsePoint = 0x00200000,
    PosixSemantics = 0x01000000,
    BackupSemantics = 0x02000000,
    DeleteOnClose = 0x04000000,
    SequentialScan = 0x08000000,
    RandomAccess = 0x10000000,
    NoBuffering = 0x20000000,
    Overlapped = 0x40000000,
    WriteThrough = 0x80000000,
}
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
