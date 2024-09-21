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

namespace NtApiDotNet.Net.Smb2
{
    /// <summary>
    /// Specifies the supported SMB2 dialects.
    /// </summary>
    public enum Smb2Dialect
    {
        /// <summary>
        /// Nothing currently negotiated.
        /// </summary>
        None = 0,
        /// <summary>
        /// SMB v2.0.2
        /// </summary>
        Smb202 = 0x202,
    }
}
