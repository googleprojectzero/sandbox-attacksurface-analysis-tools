//  Copyright 2018 Google Inc. All Rights Reserved.
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
using NtApiDotNet.Win32.Rpc;
using System;

namespace NtApiDotNet.Win32.SafeHandles
{
    internal sealed class SafeRpcBindingHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeRpcBindingHandle() : base(true)
        {
        }

        public SafeRpcBindingHandle(IntPtr handle, bool owns_handle) : base(owns_handle)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            return Win32NativeMethods.RpcBindingFree(ref handle) == 0;
        }

        public static SafeRpcBindingHandle Create(string string_binding)
        {
            return Create(string_binding, false).Result;
        }

        public static NtResult<SafeRpcBindingHandle> Create(string string_binding, bool throw_on_error)
        {
            var status = Win32NativeMethods.RpcBindingFromStringBinding(string_binding, out SafeRpcBindingHandle binding);
            if (status != Win32Error.SUCCESS)
            {
                return status.CreateResultFromDosError<SafeRpcBindingHandle>(throw_on_error);
            }
            return binding.CreateResult();
        }

        public static SafeRpcBindingHandle Create(string objuuid, string protseq, string networkaddr, string endpoint, string options)
        {
            return Create(objuuid, protseq, networkaddr, endpoint, options, true).Result;
        }

        public static NtResult<SafeRpcBindingHandle> Create(string objuuid, string protseq, string networkaddr, string endpoint, string options, bool throw_on_error)
        {
            var status = Win32NativeMethods.RpcStringBindingCompose(objuuid, protseq,
                networkaddr, endpoint, options, out SafeRpcStringHandle binding);
            if (status != Win32Error.SUCCESS)
            {
                return status.CreateResultFromDosError<SafeRpcBindingHandle>(throw_on_error);
            }
            using (binding)
            {
                return Create(binding.ToString(), throw_on_error);
            }
        }

        public override string ToString()
        {
            if (!IsInvalid && !IsClosed)
            {
                if (Win32NativeMethods.RpcBindingToStringBinding(handle, out SafeRpcStringHandle str) == 0)
                {
                    using (str)
                    {
                        return str.ToString();
                    }
                }
            }
            return string.Empty;
        }

        public static SafeRpcBindingHandle Null => new SafeRpcBindingHandle(IntPtr.Zero, false);
    }
}
