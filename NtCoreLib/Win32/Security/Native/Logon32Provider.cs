//  Copyright 2020 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Win32.Security.Native
{
    /// <summary>
    /// Logon32 provider
    /// </summary>
    public enum Logon32Provider
    {
        /// <summary>
        /// Default.
        /// </summary>
        Default = 0,
        /// <summary>
        /// Windows NT 3.5.
        /// </summary>
        WinNT35 = 1,
        /// <summary>
        /// Windows NT 4.0.
        /// </summary>
        WinNT40 = 2,
        /// <summary>
        /// Windows NT 5.0.
        /// </summary>
        WinNT50 = 3,
        /// <summary>
        /// Virtual provider.
        /// </summary>
        Virtual = 4
    }
}
