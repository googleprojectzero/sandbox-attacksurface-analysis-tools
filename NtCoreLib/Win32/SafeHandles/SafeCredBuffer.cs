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

using NtApiDotNet.Win32.Security.Native;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;

namespace NtApiDotNet.Win32.SafeHandles
{
    internal class SafeCredBuffer : SafeBufferGeneric
    {
        protected override bool ReleaseHandle()
        {
            SecurityNativeMethods.CredFree(handle);
            return true;
        }

        public SafeCredBuffer()
            : base(IntPtr.Zero, 0, true)
        {
        }

        public SafeCredBuffer(IntPtr ptr) 
            : base(ptr, 0, true)
        {
        }

        public override bool IsInvalid => handle == IntPtr.Zero;

        [ReliabilityContract(Consistency.MayCorruptInstance, Cer.MayFail)]
        public SafeCredBuffer Detach()
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try // Needed for constrained region.
            {
                IntPtr handle = DangerousGetHandle();
                SetHandleAsInvalid();
                return new SafeCredBuffer(handle);
            }
            finally
            {
            }
        }
    }
}
