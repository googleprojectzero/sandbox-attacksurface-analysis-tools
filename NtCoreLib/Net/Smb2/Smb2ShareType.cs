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
    /// Type of SMB2 share.
    /// </summary>
    public enum Smb2ShareType
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        Unknown = 0,
        [SDKName("SMB2_SHARE_TYPE_DISK")]
        Disk = 1,
        [SDKName("SMB2_SHARE_TYPE_PIPE")]
        Pipe = 2,
        [SDKName("SMB2_SHARE_TYPE_PRINT")]
        Print = 3
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
