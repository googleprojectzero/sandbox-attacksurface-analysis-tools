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
    /// DLL characteristic flags.
    /// </summary>
    [Flags]
    public enum DllCharacteristics : ushort
    {
        /// <summary>
        /// Reserved
        /// </summary>
        Reserved1 = 0x0001,
        /// <summary>
        /// Reserved
        /// </summary>
        Reserved2 = 0x0002,
        /// <summary>
        /// Reserved
        /// </summary>
        Reserved4 = 0x0004,
        /// <summary>
        /// Reserved
        /// </summary>
        Reserved8 = 0x0008,
        /// <summary>
        /// Reserved
        /// </summary>
        Reserved10 = 0x0010,
        /// <summary>
        /// Image can handle a high entropy 64-bit virtual address space. 
        /// </summary>
        HighEntropyVA = 0x0020,
        /// <summary>
        /// DLL can be relocated at load time.
        /// </summary>
        DynamicBase = 0x0040,
        /// <summary>
        /// Code Integrity checks are enforced.
        /// </summary>
        ForceIntegrity = 0x0080,
        /// <summary>
        /// Image is NX compatible.
        /// </summary>
        NxCompat = 0x0100,
        /// <summary>
        /// Isolation aware, but do not isolate the image.
        /// </summary>
        NoIsolation = 0x0200,
        /// <summary>
        /// Does not use structured exception (SE) handling. No SE handler may be called in this image.
        /// </summary>
        NoSeh = 0x0400,
        /// <summary>
        /// Do not bind the image.
        /// </summary>
        NoBind = 0x0800,
        /// <summary>
        /// Image must execute in an AppContainer.
        /// </summary>
        AppContainer = 0x1000,
        /// <summary>
        /// A WDM driver.
        /// </summary>
        WdmDriver = 0x2000,
        /// <summary>
        /// Image supports Control Flow Guard.
        /// </summary>
        GuardCF = 0x4000,
        /// <summary>
        /// Terminal Server aware. 
        /// </summary>
        TerminalServerAware = 0x8000
    }
}
