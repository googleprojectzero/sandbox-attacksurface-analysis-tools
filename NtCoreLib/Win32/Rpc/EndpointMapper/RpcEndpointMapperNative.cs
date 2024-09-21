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

using NtCoreLib.Ndr.Interop;
using NtCoreLib.Ndr.Rpc;
using NtCoreLib.Win32.Rpc.Interop;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NtCoreLib.Win32.Rpc.EndpointMapper;

internal sealed class RpcEndpointMapperNative : IRpcEndpointMapper
{
    public IEnumerable<RpcEndpoint> LookupEndpoint(RpcStringBinding search_binding, RpcEndpointInquiryFlag inquiry_flag, RpcSyntaxIdentifier? if_id_search, RpcEndPointVersionOption version, Guid? uuid_search, bool throw_on_error)
    {
        using SafeRpcBindingHandle search_handle = search_binding == null ? SafeRpcBindingHandle.Null : SafeRpcBindingHandle.Create(search_binding.ToString());
        RPC_IF_ID if_id_in = null;
        if (if_id_search.HasValue)
        {
            if_id_in = new RPC_IF_ID()
            {
                Uuid = if_id_search.Value.Uuid,
                VersMajor = if_id_search.Value.Version.Major,
                VersMinor = if_id_search.Value.Version.Minor
            };
        }

        UUID uuid_in = null;
        if (uuid_search.HasValue)
        {
            uuid_in = new UUID() { Uuid = uuid_search.Value };
        }

        Win32Error status = NativeMethods.RpcMgmtEpEltInqBegin(search_handle,
            inquiry_flag, if_id_in, version, uuid_in, out SafeRpcInquiryHandle inquiry);
        if (status != Win32Error.SUCCESS)
        {
            status.ToNtException(throw_on_error);
            yield break;
        }

        using (inquiry)
        {
            while (true)
            {
                RPC_IF_ID if_id = new();
                UUID uuid = new();
                status = NativeMethods.RpcMgmtEpEltInqNext(inquiry, if_id, out SafeRpcBindingHandle binding, uuid, out SafeRpcStringHandle annotation);
                if (status != Win32Error.SUCCESS)
                {
                    if (status != Win32Error.RPC_X_NO_MORE_ENTRIES && throw_on_error)
                    {
                        status.ToNtException();
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

    public RpcStringBinding MapEndpoint(RpcStringBinding search_binding, RpcSyntaxIdentifier if_id_search)
    {
        using var binding = SafeRpcBindingHandle.Create(search_binding.ToString(), false);

        if (!binding.IsSuccess)
            return null;

        RPC_SERVER_INTERFACE ifspec = new();
        ifspec.Length = Marshal.SizeOf(ifspec);
        ifspec.InterfaceId = if_id_search.ToSyntaxIdentifier();

        return NativeMethods.RpcEpResolveBinding(binding.Result, ref ifspec)
            .CreateWin32Result(false, () => RpcStringBinding.Parse(binding.Result.ToString())).GetResultOrDefault();
    }
}
