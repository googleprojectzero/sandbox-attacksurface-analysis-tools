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

using System.Runtime.InteropServices;

namespace NtApiDotNet
{
    /// <summary>
    /// Safe buffer to hold a security object which be deleted by RtlDeleteSecurityObject.
    /// </summary>
    public sealed class SafeSecurityObjectBuffer : SafeBuffer
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        public SafeSecurityObjectBuffer() : base(true)
        {
            Initialize(0);
        }

        /// <summary>
        /// Overridden ReleaseHandle method.
        /// </summary>
        /// <returns>True if successfully released the memory.</returns>
        protected override bool ReleaseHandle()
        {
            return NtRtl.RtlDeleteSecurityObject(ref handle).IsSuccess();
        }
    }
}
