//  Copyright 2021 Google LLC. All Rights Reserved.
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

using NtApiDotNet.Win32;
using System;
using System.Runtime.InteropServices;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace NtApiDotNet.Net.Firewall
{
    class SafeFwpmMemoryBuffer : SafeBufferGeneric
    {
        internal SafeFwpmMemoryBuffer()
            : base(IntPtr.Zero, 0, true)
        {
        }

        [DllImport("Fwpuclnt.dll", CharSet = CharSet.Unicode)]
        static extern void FwpmFreeMemory0(
            ref IntPtr p
        );

        protected override bool ReleaseHandle()
        {
            FwpmFreeMemory0(ref handle);
            return true;
        }
    }
}

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member