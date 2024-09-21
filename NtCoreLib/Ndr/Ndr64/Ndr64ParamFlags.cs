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

[Flags, Serializable]
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
public enum Ndr64ParamFlags : ushort
{
    MustSize = 0x1,
    MustFree = 0x2,
    IsPipe = 0x4,
    IsIn = 0x8,
    IsOut = 0x10,
    IsReturn = 0x20,
    IsBasetype = 0x40,
    IsByValue = 0x80,
    IsSimpleRef = 0x100,
    IsDontCallFreeInst = 0x200,
    SaveForAsyncFinish = 0x400,
    IsPartialIgnore = 0x800,
    IsForceAllocate = 0x1000,
    Reserved = 0x6000,
    UseCache = 0x8000
}
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
