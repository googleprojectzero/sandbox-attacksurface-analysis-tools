//  Copyright 2022 Google LLC. All Rights Reserved.
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

namespace NtApiDotNet.Net.Smb2
{
    /// <summary>
    /// Capability flags for shares.
    /// </summary>
    [Flags]
    public enum Smb2ShareCapabilities : uint
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        Unknown = 0,
        [SDKName("SMB2_SHARE_CAP_DFS")]
        Dfs = 0x00000008,
        [SDKName("SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY")]
        ContinuousAvailability = 0x00000010,
        [SDKName("SMB2_SHARE_CAP_SCALEOUT")]
        ScaleOut = 0x00000020,
        [SDKName("SMB2_SHARE_CAP_CLUSTER")]
        Cluster = 0x00000040,
        [SDKName("SMB2_SHARE_CAP_ASYMMETRIC")]
        Asymmetric = 0x00000080,
        [SDKName("SMB2_SHARE_CAP_REDIRECT_TO_OWNER")]
        RedirectToOwner = 0x00000100
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
