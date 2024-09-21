//  Copyright 2023 Google LLC. All Rights Reserved.
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

using Microsoft.Win32.SafeHandles;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace NtCoreLib.Native.SafeHandles
{
    internal class SafeResourceStringHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        protected override bool ReleaseHandle()
        {
            Debug.Assert(handle.ToInt64() >= 0x10000);
            Marshal.FreeHGlobal(handle);
            return true;
        }

        public SafeResourceStringHandle(int id) : base(false)
        {
            SetHandle(new IntPtr(id));
        }

        public SafeResourceStringHandle(string name) : base(true)
        {
            SetHandle(Marshal.StringToHGlobalUni(name));
        }
    }
}
