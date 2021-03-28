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
using NtApiDotNet.Win32.Security.Native;
using NtApiDotNet.Win32.Security.Policy;
using System;

namespace NtApiDotNet.Win32.SafeHandles
{
    internal class SafeLsaHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeLsaHandle(IntPtr handle, bool ownsHandle) : base(ownsHandle)
        {
            SetHandle(handle);
        }

        public SafeLsaHandle() : base(true)
        {
        }

        protected override bool ReleaseHandle()
        {
            return SecurityNativeMethods.LsaClose(handle).IsSuccess();
        }

        internal static NtResult<SafeLsaHandle> OpenPolicy(string system_name, LsaPolicyAccessRights desired_access, bool throw_on_error)
        {
            UnicodeString str = system_name != null ? new UnicodeString(system_name) : null;

            return SecurityNativeMethods.LsaOpenPolicy(str, new ObjectAttributes(),
                desired_access, out SafeLsaHandle policy).CreateResult(throw_on_error, () => policy);
        }
    }
}
