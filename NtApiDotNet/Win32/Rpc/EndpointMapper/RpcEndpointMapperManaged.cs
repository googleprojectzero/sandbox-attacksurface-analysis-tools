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

        private static twr_p_t BuildProtocolTower(string string_binding, RpcInterfaceId interface_id)
        {
            RpcStringBinding binding = RpcStringBinding.Parse(string_binding);
            return default;
        }

        private static RpcStringBinding GetStringBinding(string search_binding)
        {
            if (string.IsNullOrEmpty(search_binding))
            {
                if (NtObjectUtils.IsWindows)
                   return new RpcStringBinding(RpcProtocolSequence.LRPC, endpoint: "epmapper");
                else
                   return new RpcStringBinding(RpcProtocolSequence.Tcp, endpoint: "135");
            }
            else if (!RpcStringBinding.TryParse(search_binding, out RpcStringBinding string_binding))
            {
                return null;
            }
            else
            {
                switch (string_binding.ProtocolSequence.ToLower())
                {
                    case RpcProtocolSequence.LRPC:
                        return new RpcStringBinding(RpcProtocolSequence.LRPC, endpoint: "epmapper");
                    case RpcProtocolSequence.NamedPipe:
                        return new RpcStringBinding(RpcProtocolSequence.NamedPipe, string_binding.NetworkAddress, @"\pipe\epmapper");
                    case RpcProtocolSequence.Tcp:
                        return new RpcStringBinding(RpcProtocolSequence.Tcp, string_binding.NetworkAddress, "135");
                    case RpcProtocolSequence.Container:
                        return new RpcStringBinding(RpcProtocolSequence.Container, string_binding.NetworkAddress, "DA32E281-383E-49A1-900A-AF3B74B90B0E");
                    case RpcProtocolSequence.Http:
                        return new RpcStringBinding(RpcProtocolSequence.Http, string_binding.NetworkAddress, "593");
                    default:
                        return null;
                }
            }
        }

        public IEnumerable<RpcEndpoint> LookupEndpoint(string search_binding, RpcEndpointInquiryFlag inquiry_flag, 
            RpcInterfaceId if_id_search, RpcEndPointVersionOption version, System.Guid? uuid_search, bool throw_on_error = true)
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

                                if (!RpcProtocolTower.TryParse(entry.tower.GetValue().tower_octet_string, out RpcProtocolTower tower))
                                    continue;
                                var if_id_floor = tower.Interface;
                                if (if_id_floor == null)
                                    continue;

                                RpcStringBinding binding = tower.GetStringBinding(entry.obj);
                                if (binding == null)
                                    continue;

                                eps.Add(new RpcEndpoint(if_id_floor.Uuid, if_id_floor.Version, binding, entry.annotation, true, tower));
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
