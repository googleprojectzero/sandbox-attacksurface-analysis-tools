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

using System;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Flags for message encryption.
    /// </summary>
    [Flags]
    public enum SecurityQualityOfProtectionFlags : uint
    {
        /// <summary>
        /// None.
        /// </summary>
        None = 0,
        /// <summary>
        /// Wrap out of bound data.
        /// </summary>
        WrapOOBData = 0x40000000,
        /// <summary>
        /// Wrap but don't encrypt.
        /// </summary>
        WrapNoEncrypt = 0x80000001
    }
}
