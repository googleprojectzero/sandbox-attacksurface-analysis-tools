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
    /// Flags for an SMB2 share.
    /// </summary>
    [Flags]
    public enum Smb2ShareFlags : uint
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        [SDKName("SMB2_SHAREFLAG_MANUAL_CACHING")]
        ManualCaching = 0x00000000,
        [SDKName("SMB2_SHAREFLAG_AUTO_CACHING")]
        AutoCaching = 0x00000010,
        [SDKName("SMB2_SHAREFLAG_VDO_CACHING")]
        VDOCaching = 0x00000020,
        [SDKName("SMB2_SHAREFLAG_NO_CACHING")]
        NoCaching = 0x00000030,
        [SDKName("SMB2_SHAREFLAG_DFS")]
        Dfs = 0x00000001,
        [SDKName("SMB2_SHAREFLAG_DFS_ROOT")]
        DfsRoot = 0x00000002,
        [SDKName("SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS")]
        RestrictExclusiveOpens = 0x00000100,
        [SDKName("SMB2_SHAREFLAG_FORCE_SHARED_DELETE")]
        ForceSharedDelete = 0x00000200,
        [SDKName("SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING")]
        AllowNamespaceCaching = 0x00000400,
        [SDKName("SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM")]
        AccessBasedDirectoryEnum = 0x00000800,
        [SDKName("SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK")]
        ForceLevelIIOplock = 0x00001000,
        [SDKName("SMB2_SHAREFLAG_ENABLE_HASH_V1")]
        EnableHashV1 = 0x00002000,
        [SDKName("SMB2_SHAREFLAG_ENABLE_HASH_V2")]
        EnableHashV2 = 0x00004000,
        [SDKName("SMB2_SHAREFLAG_ENCRYPT_DATA")]
        EncryptData = 0x00008000,
        [SDKName("SMB2_SHAREFLAG_IDENTITY_REMOTING")]
        IdentityRemoting = 0x00040000,
        [SDKName("SMB2_SHAREFLAG_COMPRESS_DATA")]
        CompressData = 0x00100000,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
