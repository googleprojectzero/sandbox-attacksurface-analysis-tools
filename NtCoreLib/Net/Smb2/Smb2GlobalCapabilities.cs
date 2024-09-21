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

using System;

namespace NtApiDotNet.Net.Smb2
{
    [Flags]
    internal enum Smb2GlobalCapabilities
    {
        DFS = 0x00000001,
        LEASING = 0x00000002,
        LARGE_MTU = 0x00000004,
        MULTI_CHANNEL = 0x00000008,
        PERSISTENT_HANDLES = 0x00000010,
        DIRECTORY_LEASING = 0x00000020,
        ENCRYPTION = 0x00000040
    }
}
