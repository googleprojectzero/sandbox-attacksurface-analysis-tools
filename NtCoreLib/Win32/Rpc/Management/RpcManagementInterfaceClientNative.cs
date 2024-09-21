//  Copyright 2023 Google LLC. All Rights Reserved.
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

using NtCoreLib.Ndr.Rpc;
using NtCoreLib.Win32.Rpc.EndpointMapper;
using NtCoreLib.Win32.Rpc.Interop;
using NtCoreLib.Win32.Rpc.Transport;
using System;
using System.Linq;

namespace NtCoreLib.Win32.Rpc.Management;

internal sealed class RpcManagementInterfaceClientNative : IRpcManagementInterface
{
    public NtResult<RpcSyntaxIdentifier[]> rpc_mgmt_inq_if_ids(RpcStringBinding binding, bool throw_on_error)
    {
        using var binding_handle = binding.ToHandle(throw_on_error);
        if (!binding_handle.IsSuccess)
            return binding_handle.Cast<RpcSyntaxIdentifier[]>();
        Win32Error status = NativeMethods.RpcMgmtInqIfIds(binding_handle.Result, out SafeRpcIfIdVectorHandle if_id_vector);
        // If the RPC server doesn't exist return an empty list.
        if (status == Win32Error.RPC_S_SERVER_UNAVAILABLE)
        {
            return new RpcSyntaxIdentifier[0].CreateResult();
        }
        if (status != Win32Error.SUCCESS)
        {
            return status.CreateResultFromDosError<RpcSyntaxIdentifier[]>(throw_on_error);
        }

        using (if_id_vector)
        {
            return if_id_vector.GetIfIds().Select(if_id =>
                new RpcSyntaxIdentifier(if_id)).ToArray().CreateResult();
        }
    }

    public NtResult<string> rpc_mgmt_inq_princ_name(RpcStringBinding binding, RpcAuthenticationType authn_proto, bool throw_on_error)
    {
        using var binding_handle = binding.ToHandle(false);
        if (!binding_handle.IsSuccess)
        {
            return binding_handle.Cast<string>();
        }

        return NativeMethods.RpcMgmtInqServerPrincName(binding_handle.Result, authn_proto,
            out SafeRpcStringHandle spn).CreateWin32Result(throw_on_error, () =>
            {
                using (spn)
                {
                    return spn.ToString();
                }
            }
            );
    }

    public NtResult<int[]> rpc_mgmt_inq_stats(RpcStringBinding binding, bool throw_on_error)
    {
        throw new NotImplementedException();
    }

    public NtResult<bool> rpc_mgmt_is_server_listening(RpcStringBinding binding, bool throw_on_error)
    {
        throw new NotImplementedException();
    }

    public NtStatus rpc_mgmt_stop_server_listening(RpcStringBinding binding, bool throw_on_error)
    {
        throw new NotImplementedException();
    }
}