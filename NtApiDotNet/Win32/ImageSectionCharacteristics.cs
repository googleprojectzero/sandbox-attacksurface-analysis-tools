//  Copyright 2016, 2017 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Characteristic flags for image section.
    /// </summary>
    [Flags]
    public enum ImageSectionCharacteristics : uint
    {
        /// <summary>
        /// None.
        /// </summary>
        None = 0,
        /// <summary>
        /// Section is code.
        /// </summary>
        Code = 0x00000020,
        /// <summary>
        /// Section is initialized data.
        /// </summary>
        InitiailizedData = 0x00000040,
        /// <summary>
        /// Section is uninitialized data.
        /// </summary>
        UninitializedData = 0x00000080,
        /// <summary>
        /// Section is shared.
        /// </summary>
        Shared = 0x10000000,
        /// <summary>
        /// Section is executable.
        /// </summary>
        Execute = 0x20000000,
        /// <summary>
        /// Section is readable.
        /// </summary>
        Read = 0x40000000,
        /// <summary>
        /// Section is writable.
        /// </summary>
        Write = 0x80000000,
    }
}
