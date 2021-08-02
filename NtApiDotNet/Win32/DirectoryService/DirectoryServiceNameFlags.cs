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

namespace NtApiDotNet.Win32.DirectoryService
{
    /// <summary>
    /// Directory services name flags.
    /// </summary>
    [Flags, SDKName("DS_NAME_FLAGS")]
    public enum DirectoryServiceNameFlags
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        [SDKName("DS_NAME_NO_FLAGS")]
        None = 0,
        [SDKName("DS_NAME_FLAG_SYNTACTICAL_ONLY")]
        SyntacticalOnly = 1,
        [SDKName("DS_NAME_FLAG_EVAL_AT_DC")]
        EvalAtDC = 2,
        [SDKName("DS_NAME_FLAG_GCVERIFY")]
        GCVerify = 4,
        [SDKName("DS_NAME_FLAG_TRUST_REFERRAL")]
        TrustReferral = 8
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
