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
        private CrackedBindingString _cracked_binding;

        private CrackedBindingString GetCrackedBinding()
        {
            if (IsClosed)
            {
                throw new ObjectDisposedException("CrackedBindingString");
            }
            if (_cracked_binding == null)
            {
                _cracked_binding = new CrackedBindingString(ToString());
            }
            return _cracked_binding;
        }

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

        public string ObjUuid => GetCrackedBinding().ObjUuid;
        public string Protseq => GetCrackedBinding().Protseq;
        public string NetworkAddr => GetCrackedBinding().NetworkAddr;
        public string Endpoint => GetCrackedBinding().Endpoint;
        public string NetworkOptions => GetCrackedBinding().NetworkOptions;

        public static SafeRpcBindingHandle Create(string string_binding)
        {
            int status = Win32NativeMethods.RpcBindingFromStringBinding(string_binding, out SafeRpcBindingHandle binding);
            if (status != 0)
            {
                throw new SafeWin32Exception(status);
            }
            binding._cracked_binding = new CrackedBindingString(string_binding);
            return binding;
        }

        public static SafeRpcBindingHandle Create(string objuuid, string protseq, string networkaddr, string endpoint, string options)
        {
            int status = Win32NativeMethods.RpcStringBindingCompose(objuuid, protseq,
                networkaddr, endpoint, options, out SafeRpcStringHandle binding);
            if (status != 0)
            {
                throw new SafeWin32Exception(status);
            }
            using (binding)
            {
                return Create(binding.ToString());
            }
        }

        public static string Compose(string objuuid, string protseq, string networkaddr, string endpoint, string options)
        {
            using (var binding = Create(objuuid, protseq, networkaddr, endpoint, options))
            {
                return binding.ToString();
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
