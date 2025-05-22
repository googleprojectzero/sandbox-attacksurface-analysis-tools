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
//  Based on PH source https://github.com/winsiderss/systeminformer/blob/85723cfb22b03ed7c068bbe784385dd64551a14b/phnt/include/ntafd.h

using System;

namespace NtCoreLib.Kernel.Net;

/// <summary>
/// Flags for AFD endpoint setup.
/// </summary>
[Flags]
public enum AfdEndpointFlags : uint
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    None = 0,
    ConnectionLess = 1,
    MessageMode = 1 << 4,
    Raw = 1 << 5,
    Multipoint = 1 << 9,
    C_Root = 1 << 10,
    D_Root = 1 << 14,
    IgnoreTDI = 1 << 15,
    RioSocket = 1 << 19,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
