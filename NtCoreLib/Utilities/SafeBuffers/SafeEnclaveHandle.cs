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

using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;

namespace NtApiDotNet.Utilities.SafeBuffers
{
    internal class SafeEnclaveHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeEnclaveHandle(IntPtr base_address) : base(true)
        {
            SetHandle(base_address);
        }

        protected override bool ReleaseHandle()
        {
            return NtLdrNative.LdrDeleteEnclave(handle).IsSuccess();
        }

        /// <summary>
        /// Detaches the current handle and allocates a new one.
        /// </summary>
        /// <returns>The detached buffer.</returns>
        /// <remarks>The original buffer will become invalid after this call.</remarks>
        [ReliabilityContract(Consistency.MayCorruptInstance, Cer.MayFail)]
        public SafeEnclaveHandle Detach()
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try // Needed for constrained region.
            {
                IntPtr handle = DangerousGetHandle();
                SetHandleAsInvalid();
                return new SafeEnclaveHandle(handle);
            }
            finally
            {
            }
        }
    }
}
