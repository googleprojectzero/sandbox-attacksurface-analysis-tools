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
    public enum FirewallFilterEnumFlags
    {
        None = 0,
        [SDKName("FWP_FILTER_ENUM_FLAG_BEST_TERMINATING_MATCH")]
        BestTerminatingMatch = 0x00000001,
        [SDKName("FWP_FILTER_ENUM_FLAG_SORTED")]
        Sorted = 0x00000002,
        [SDKName("FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY")]
        BoottimeOnly = 0x00000004,
        [SDKName("FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME")]
        IncludeBoottime = 0x00000008,
        [SDKName("FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED")]
        IncludeDisabled = 0x00000010,
        [SDKName("FWP_FILTER_ENUM_FLAG_RESERVED1")]
        Reserved1 = 0x00000020,
    }
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member