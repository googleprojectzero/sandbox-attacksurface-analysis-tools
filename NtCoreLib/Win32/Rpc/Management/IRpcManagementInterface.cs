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
using NtCoreLib.Win32.Rpc.Transport;

namespace NtCoreLib.Win32.Rpc.Management;

internal interface IRpcManagementInterface
{
    NtResult<RpcSyntaxIdentifier[]> rpc_mgmt_inq_if_ids(RpcStringBinding binding, bool throw_on_error);
    NtResult<int[]> rpc_mgmt_inq_stats(RpcStringBinding binding, bool throw_on_error);
    NtResult<bool> rpc_mgmt_is_server_listening(RpcStringBinding binding, bool throw_on_error);
    NtStatus rpc_mgmt_stop_server_listening(RpcStringBinding binding, bool throw_on_error);
    NtResult<string> rpc_mgmt_inq_princ_name(RpcStringBinding binding, RpcAuthenticationType authn_proto, bool throw_on_error);
}
