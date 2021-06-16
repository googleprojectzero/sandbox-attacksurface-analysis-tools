//  Copyright 2021 Google LLC. All Rights Reserved.
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

using NtApiDotNet.Utilities.Reflection;
using System;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace NtApiDotNet.Net.Firewall
{
    [Flags]
    public enum FirewallSessionFlags
    {
        None = 0,
        [SDKName("FWPM_SESSION_FLAG_DYNAMIC")]
        Dynamic = 0x00000001,
        [SDKName("FWPM_SESSION_FLAG_RESERVED")]
        Reserved = 0x10000000
    }
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member