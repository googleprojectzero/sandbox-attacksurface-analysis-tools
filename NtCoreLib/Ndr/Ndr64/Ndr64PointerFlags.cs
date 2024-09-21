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

namespace NtCoreLib.Ndr.Ndr64;

/// <summary>
/// Pointer flags.
/// </summary>
[Flags]
[Serializable]
public enum Ndr64PointerFlags : byte
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    AllocateAllNodes = 0x01,
    DontFree = 0x02,
    AllocatedOnStack = 0x04,
    SimplePointer = 0x08,
    PointerDeref = 0x10,
    MaybeNullSizeIs = 0x20,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
