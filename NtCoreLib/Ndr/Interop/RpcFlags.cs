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

namespace NtCoreLib.Ndr.Interop;

[Flags]
internal enum RpcFlags : uint
{
    None = 0,
    HasPipes = 0x0001,
    Message = 0x01000000,
    AutoComplete = 0x08000000,
    LocalCall = 0x10000000,
    InputSynchronous = 0x20000000,
    Asynchronous = 0x40000000,
    NonNdr = 0x80000000,
    HasMultiSyntaxes = 0x02000000,
    HasCallback = 0x04000000,
}
