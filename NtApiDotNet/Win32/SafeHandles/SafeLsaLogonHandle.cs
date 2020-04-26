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
using NtApiDotNet.Win32.Security.Native;
using System;

namespace NtApiDotNet.Win32.SafeHandles
{
    internal class SafeLsaLogonHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeLsaLogonHandle(IntPtr handle, bool ownsHandle) : base(ownsHandle)
        {
            SetHandle(handle);
        }

        public SafeLsaLogonHandle() : base(true)
        {
        }

        protected override bool ReleaseHandle()
        {
            return SecurityNativeMethods.LsaDeregisterLogonProcess(handle).IsSuccess();
        }

        internal static NtResult<SafeLsaLogonHandle> Connect(bool throw_on_error)
        {
            if (!SecurityNativeMethods.LsaRegisterLogonProcess(new LsaString("NtApiDotNet"), out SafeLsaLogonHandle hlsa, out uint _).IsSuccess())
            {
                return SecurityNativeMethods.LsaConnectUntrusted(out hlsa).CreateResult(throw_on_error, () => hlsa);
            }
            return hlsa.CreateResult();
        }
    }
}
