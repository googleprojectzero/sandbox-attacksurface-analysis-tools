//  Copyright 2016 Google Inc. All Rights Reserved.
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

namespace NtApiDotNet
{
#pragma warning disable 1591
    /// <summary>
    /// Safe SID buffer.
    /// </summary>
    /// <remarks>This is used to return values from the RTL apis which need to be freed using RtlFreeSid</remarks>
    public sealed class SafeSidBufferHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeSidBufferHandle(IntPtr sid, bool owns_handle) : base(owns_handle)
        {
            SetHandle(sid);
        }

        public SafeSidBufferHandle() : base(true)
        {
        }

        public static SafeSidBufferHandle Null { get
            { return new SafeSidBufferHandle(IntPtr.Zero, false); }
        }

        public int Length
        {
            get { return NtRtl.RtlLengthSid(handle); }
        }

        public Sid ToSid()
        {
            return new Sid(DangerousGetHandle());
        }

        protected override bool ReleaseHandle()
        {
            if (!IsInvalid)
            {
                NtRtl.RtlFreeSid(handle);
                handle = IntPtr.Zero;
            }
            return true;
        }
    }

#pragma warning restore 1591
}
