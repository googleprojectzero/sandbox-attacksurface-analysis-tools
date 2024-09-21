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

namespace NtApiDotNet.Net.Smb2
{
    /// <summary>
    /// Requested oplock level for SMB2 file.
    /// </summary>
    public enum Smb2OplockLevel
    {
        [SDKName("SMB2_OPLOCK_LEVEL_NONE")]
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0x00,
        [SDKName("SMB2_OPLOCK_LEVEL_II")]
        LevelII = 0x01,
        [SDKName("SMB2_OPLOCK_LEVEL_EXCLUSIVE")]
        Exclusive = 0x08,
        [SDKName("SMB2_OPLOCK_LEVEL_BATCH")]
        Batch = 0x09,
        [SDKName("SMB2_OPLOCK_LEVEL_LEASE")]
        Lease = 0xFF
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
