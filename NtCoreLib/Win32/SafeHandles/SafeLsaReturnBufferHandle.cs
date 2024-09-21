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

using NtApiDotNet.Win32.Security.Native;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;

namespace NtApiDotNet.Win32.SafeHandles
{
    internal class SafeLsaReturnBufferHandle : SafeBufferGeneric
    {
        protected override bool ReleaseHandle()
        {
            return SecurityNativeMethods.LsaFreeReturnBuffer(handle).IsSuccess();
        }

        public SafeLsaReturnBufferHandle(IntPtr handle, bool owns_handle)
            : base(handle, 0, owns_handle)
        {
        }

        public SafeLsaReturnBufferHandle() 
            : base(true)
        {
        }

        public override bool IsInvalid => handle == IntPtr.Zero;

        /// <summary>
        /// Detaches the current buffer and allocates a new one.
        /// </summary>
        /// <returns>The detached buffer.</returns>
        /// <remarks>The original buffer will become invalid after this call.</remarks>
        [ReliabilityContract(Consistency.MayCorruptInstance, Cer.MayFail)]
        public SafeLsaReturnBufferHandle Detach()
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try // Needed for constrained region.
            {
                IntPtr handle = DangerousGetHandle();
                SetHandleAsInvalid();
                var ret = new SafeLsaReturnBufferHandle(handle, true);
                ret.InitializeLength(LongLength);
                return ret;
            }
            finally
            {
            }
        }
    }
}
