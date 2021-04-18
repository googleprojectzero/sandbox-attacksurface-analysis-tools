//  Copyright 2021 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Win32.Security.Policy
{
    /// <summary>
    /// Flags for looking up SID names.
    /// </summary>
    [Flags]
    public enum LsaLookupSidOptionFlags : uint
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        [SDKName("LSA_LOOKUP_RETURN_LOCAL_NAMES")]
        ReturnLocalNames = 0,
        [SDKName("LSA_LOOKUP_PREFER_INTERNET_NAMES")]
        PreferInternetNames = 0x40000000,
        [SDKName("LSA_LOOKUP_DISALLOW_CONNECTED_ACCOUNT_INTERNET_SID")]
        DisallowConnectedAccountInternetSid = 0x80000000
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
