//  Copyright 2022 Google LLC. All Rights Reserved.
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

using NtApiDotNet.Ndr;
using NtApiDotNet.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Rpc.EndpointMapper
{
    internal sealed class RpcEndpointMapperNative : IRpcEndpointMapper
    {
        private static Win32Error ResolveBinding(SafeRpcBindingHandle binding, Guid interface_id, Version interface_version)
        {
            RPC_SERVER_INTERFACE ifspec = new RPC_SERVER_INTERFACE();
            ifspec.Length = Marshal.SizeOf(ifspec);
            ifspec.InterfaceId.SyntaxGUID = interface_id;
            ifspec.InterfaceId.SyntaxVersion = interface_version.ToRpcVersion();

            return Win32NativeMethods.RpcEpResolveBinding(binding, ref ifspec);
        }

        private static string MapBindingToBindingString(NtResult<SafeRpcBindingHandle> binding, Guid interface_id, Version interface_version)
        {
            if (!binding.IsSuccess)
                return string.Empty;

            if (ResolveBinding(binding.Result, interface_id, interface_version) != Win32Error.SUCCESS)
            {
                return string.Empty;
            }
            return binding.Result.ToString();
        }

        public IEnumerable<RpcEndpoint> LookupEndpoint(string search_binding, RpcEndpointInquiryFlag inquiry_flag, RpcInterfaceId if_id_search, RpcEndPointVersionOption version, Guid? uuid_search, bool throw_on_error)
        {
            using (SafeRpcBindingHandle search_handle = string.IsNullOrEmpty(search_binding) ? SafeRpcBindingHandle.Null : SafeRpcBindingHandle.Create(search_binding))
            {
                RPC_IF_ID if_id_in = null;
                if (if_id_search != null)
                {
                    if_id_in = new RPC_IF_ID()
                    {
                        Uuid = if_id_search.Uuid,
                        VersMajor = (ushort)if_id_search.Version.Major,
                        VersMinor = (ushort)if_id_search.Version.Minor
                    };
                }

                UUID uuid_in = null;
                if (uuid_search.HasValue)
                {
                    uuid_in = new UUID() { Uuid = uuid_search.Value };
                }

                int status = Win32NativeMethods.RpcMgmtEpEltInqBegin(search_handle,
                    inquiry_flag, if_id_in, version, uuid_in, out SafeRpcInquiryHandle inquiry);
                if (status != 0)
                {
                    if (throw_on_error)
                        throw new SafeWin32Exception(status);
                    yield break;
                }

                using (inquiry)
                {
                    while (true)
                    {
                        RPC_IF_ID if_id = new RPC_IF_ID();
                        UUID uuid = new UUID();
                        status = Win32NativeMethods.RpcMgmtEpEltInqNext(inquiry, if_id, out SafeRpcBindingHandle binding, uuid, out SafeRpcStringHandle annotation);
                        if (status != 0)
                        {
                            if (status != 1772 && throw_on_error)
                            {
                                throw new SafeWin32Exception(status);
                            }
                            break;
                        }
                        try
                        {
                            yield return new RpcEndpoint(if_id, uuid, annotation, binding, true);
                        }
                        finally
                        {
                            binding.Dispose();
                            annotation.Dispose();
                        }
                    }
                }
            }
        }

        public string MapEndpoint(string search_binding, RpcInterfaceId if_id_search)
        {
            using (var binding = SafeRpcBindingHandle.Create(search_binding, false))
            {
                return MapBindingToBindingString(binding, if_id_search.Uuid, if_id_search.Version);
            }
        }
    }
}
