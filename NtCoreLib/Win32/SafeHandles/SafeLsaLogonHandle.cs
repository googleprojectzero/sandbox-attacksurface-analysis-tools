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
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.SafeHandles
{
    internal struct LsaCallPackageResponse : IDisposable
    {
        public NtStatus Status;
        public SafeLsaReturnBufferHandle Buffer;

        public void Dispose()
        {
            ((IDisposable)Buffer)?.Dispose();
        }
    }

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
            var result = RegisterLogonProcess("NtApiDotNet", false);
            if (result.IsSuccess)
                return result;

            return ConnectUntrusted(throw_on_error);
        }

        internal static NtResult<SafeLsaLogonHandle> ConnectUntrusted(bool throw_on_error)
        {
            return SecurityNativeMethods.LsaConnectUntrusted(out SafeLsaLogonHandle hlsa).CreateResult(throw_on_error, () => hlsa);
        }

        internal static NtResult<SafeLsaLogonHandle> RegisterLogonProcess(string process_name, bool throw_on_error)
        {
            return SecurityNativeMethods.LsaRegisterLogonProcess(new LsaString(process_name), 
                out SafeLsaLogonHandle hlsa, out uint _).CreateResult(throw_on_error, () => hlsa);
        }

        public NtResult<uint> LookupAuthPackage(string auth_package, bool throw_on_error)
        {
            return SecurityNativeMethods.LsaLookupAuthenticationPackage(
                    this, new LsaString(auth_package), out uint auth_pkg).CreateResult(throw_on_error, () => auth_pkg);
        }

        private static LsaCallPackageResponse CreateResponse(NtStatus status, SafeLsaReturnBufferHandle buffer, int length)
        {
            if (!(buffer?.IsInvalid ?? true))
            {
                buffer?.InitializeLength(length);
            }
            return new LsaCallPackageResponse()
            {
                Status = status,
                Buffer = buffer
            };
        }

        public NtResult<LsaCallPackageResponse> CallPackage(uint auth_package, SafeBuffer buffer, bool throw_on_error)
        {
            return SecurityNativeMethods.LsaCallAuthenticationPackage(this, auth_package, buffer, buffer.GetLength(),
                out SafeLsaReturnBufferHandle ret, out int ret_length, out NtStatus status).CreateResult(throw_on_error, () => CreateResponse(status, ret, ret_length));
        }
    }
}
