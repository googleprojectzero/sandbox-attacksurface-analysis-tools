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

using NtApiDotNet.Win32.SafeHandles;
using System;

namespace NtApiDotNet.Win32.Rpc
{
    internal class CrackedBindingString
    {
        public string ObjUuid { get; }
        public string Protseq { get; }
        public string NetworkAddr { get; }
        public string Endpoint { get; }
        public string NetworkOptions { get; }
        public Guid ObjUuidParsed { get; }

        public CrackedBindingString(string string_binding)
        {
            SafeRpcStringHandle objuuid = null;
            SafeRpcStringHandle protseq = null;
            SafeRpcStringHandle endpoint = null;
            SafeRpcStringHandle networkaddr = null;
            SafeRpcStringHandle networkoptions = null;

            try
            {
                var status = Win32NativeMethods.RpcStringBindingParse(string_binding,
                    out objuuid, out protseq, out networkaddr, out endpoint, out networkoptions);
                if (status == Win32Error.SUCCESS)
                {
                    ObjUuid = objuuid.ToString();
                    if (Guid.TryParse(ObjUuid, out Guid guid))
                    {
                        ObjUuidParsed = guid;
                    }
                    Protseq = protseq.ToString();
                    Endpoint = endpoint.ToString();
                    NetworkAddr = networkaddr.ToString();
                    NetworkOptions = networkoptions.ToString();
                }
                else
                {
                    ObjUuid = string.Empty;
                    Protseq = string.Empty;
                    Endpoint = string.Empty;
                    NetworkAddr = string.Empty;
                    NetworkOptions = string.Empty;
                }
            }
            finally
            {
                objuuid?.Dispose();
                protseq?.Dispose();
                endpoint?.Dispose();
                networkaddr?.Dispose();
                networkoptions?.Dispose();
            }
        }
    }
}
