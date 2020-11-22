//  Copyright 2018 Google Inc. All Rights Reserved.
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
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.SafeHandles
{
    internal sealed class SafeRpcStringHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeRpcStringHandle() : base(true)
        {
        }

        public SafeRpcStringHandle(IntPtr handle, bool owns_handle) : base(owns_handle)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            return Win32NativeMethods.RpcStringFree(ref handle) == 0;
        }

        public override string ToString()
        {
            if (!IsInvalid && !IsClosed)
            {
                return Marshal.PtrToStringUni(handle);
            }
            return string.Empty;
        }
    }
}
