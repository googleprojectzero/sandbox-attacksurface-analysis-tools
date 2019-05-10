//  Copyright 2019 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet.Win32
{
    internal sealed class SafeEventRegHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        protected override bool ReleaseHandle()
        {
            return Win32NativeMethods.EventUnregister(handle) == Win32Error.SUCCESS;
        }

        public SafeEventRegHandle(IntPtr handle, bool owns_handle) 
            : base(owns_handle)
        {
            SetHandle(handle);
        }

        public SafeEventRegHandle()
            : base(true)
        {
        }
    }
}
