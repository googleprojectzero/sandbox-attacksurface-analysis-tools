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

using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;

namespace NtApiDotNet.Win32.SafeHandles
{
    internal class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeServiceHandle() : base(true)
        {
        }

        public SafeServiceHandle(IntPtr handle, bool owns_handle)
            : base(owns_handle)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            return Win32NativeMethods.CloseServiceHandle(handle);
        }

        [ReliabilityContract(Consistency.MayCorruptInstance, Cer.MayFail)]
        public SafeServiceHandle Detach()
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try // Needed for constrained region.
            {
                IntPtr handle = DangerousGetHandle();
                SetHandleAsInvalid();
                return new SafeServiceHandle(handle, true);
            }
            finally
            {
            }
        }
    }
}
