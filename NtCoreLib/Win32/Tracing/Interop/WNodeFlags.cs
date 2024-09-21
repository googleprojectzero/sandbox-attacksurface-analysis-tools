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

using System;

namespace NtCoreLib.Win32.Tracing.Interop;

[Flags]
internal enum WNodeFlags
{
    None = 0,
    AllData = 0x00000001,
    SingleInstance = 0x00000002,
    SingleItem = 0x00000004,
    EventItem = 0x00000008,
    FixedInstanceSize = 0x00000010,
    TooSmall = 0x00000020,
    InstancesSame = 0x00000040,
    StaticInstanceNames = 0x00000080,
    Internal = 0x00000100,
    UseTimestamp = 0x00000200,
    PersistEvent = 0x00000400,
    Reference = 0x00002000,
    AnsiInstanceNames = 0x00004000,
    MethodItem = 0x00008000,
    PDOInstanceNames = 0x00010000,
    TracedGuid = 0x00020000,
    LogWNode = 0x00040000,
    UseGuidPtr = 0x00080000,
    UseMofPtr = 0x00100000,
    NoHeader = 0x00200000,
    SendDataBlock = 0x00400000,
    VersionedProperties = 0x00800000,
}
#pragma warning restore 1591
