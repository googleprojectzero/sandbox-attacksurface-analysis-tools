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

using NtApiDotNet.Ndr.Marshal;
using NtApiDotNet.Win32.Rpc.Transport;
using System;
using System.Collections.Generic;

namespace NtApiDotNet.Win32.Rpc.EndpointMapper
{
    internal class RpcEndpointMapperManaged : IRpcEndpointMapper
    {
        private const int STATUS_NO_INTERFACES = 0x16c9a0d6;

        private static RpcStringBinding GetStringBinding(string search_binding)
        {
            if (string.IsNullOrEmpty(search_binding))
            {
                if (NtObjectUtils.IsWindows)
                   return new RpcStringBinding("ncalrpc", endpoint: "epmapper");
                else
                   return new RpcStringBinding("ncacn_ip_tcp", endpoint: "135");
            }
            else if (!RpcStringBinding.TryParse(search_binding, out RpcStringBinding string_binding))
            {
                return null;
            }
            else
            {
                switch (string_binding.ProtocolSequence.ToLower())
                {
                    case "ncalrpc":
                        return new RpcStringBinding("ncalrpc", endpoint: "epmapper");
                    case "ncacn_np":
                        return new RpcStringBinding("ncacn_np", string_binding.NetworkAddress, @"\pipe\epmapper");
                    case "ncacn_ip_tcp":
                        return new RpcStringBinding("ncacn_ip_tcp", string_binding.NetworkAddress, "135");
                    default:
                        return null;
                }
            }
        }

        public IEnumerable<RpcEndpoint> LookupEndpoint(string search_binding, RpcEndpointInquiryFlag inquiry_flag, RpcInterfaceId if_id_search, RpcEndPointVersionOption version, System.Guid? uuid_search, bool throw_on_error = true)
        {
            const int MAX_ENTRIES = 100;
            List<RpcEndpoint> eps = new List<RpcEndpoint>();

            RpcStringBinding string_binding = GetStringBinding(search_binding);
            if (string_binding == null)
            {
                if (throw_on_error)
                    throw new SafeWin32Exception(Win32Error.RPC_S_INVALID_STRING_BINDING);
                return Array.Empty<RpcEndpoint>();
            }

            try
            {
                using (var client = new EpMapperClient())
                {
                    client.Connect(string_binding.ToString(), new RpcTransportSecurity() { AuthenticationLevel = RpcAuthenticationLevel.None });

                    NdrContextHandle entry_handle = NdrContextHandle.Empty;
                    RPC_IF_ID_EPT? if_id = if_id_search?.ToRpcIfId();

                    client.ept_lookup((int)inquiry_flag, uuid_search, if_id, (int)version, ref entry_handle,
                        MAX_ENTRIES, out int num_ent, out ept_entry_t[] entries, out int status);
                    try
                    {
                        while (status == 0)
                        {
                            foreach (var entry in entries)
                            {
                                if (entry.tower == null)
                                    continue;

                                if (RpcProtocolTowerFloor.TryParse(entry.tower.GetValue().tower_octet_string, out List<RpcProtocolTowerFloor> floors))
                                {
                                    if (floors.Count < 4)
                                    {
                                        continue;
                                    }

                                    var if_id_floor = floors[0].GetIdentifier();

                                    if (if_id_floor == null)
                                        continue;

                                    RpcStringBinding binding = floors[3].GetStringBinding(entry.obj);
                                    if (binding == null)
                                        continue;

                                    eps.Add(new RpcEndpoint(if_id_floor.Item1, if_id_floor.Item2, binding, entry.annotation, true));
                                }
                            }
                            if (num_ent < MAX_ENTRIES)
                                break;

                            client.ept_lookup((int)inquiry_flag, uuid_search, null, (int)version,
                                ref entry_handle, MAX_ENTRIES, out num_ent, out entries, out status);
                        }
                    }
                    finally
                    {
                        if (!entry_handle.IsInvalid)
                            client.ept_lookup_handle_free(ref entry_handle, out status);
                    }
                }
            }
            catch
            {
                if (throw_on_error)
                    throw;
            }
            return eps.AsReadOnly();
        }

        public string MapEndpoint(string search_binding, RpcInterfaceId if_id_search)
        {
            throw new NotImplementedException();
        }
    }
}
