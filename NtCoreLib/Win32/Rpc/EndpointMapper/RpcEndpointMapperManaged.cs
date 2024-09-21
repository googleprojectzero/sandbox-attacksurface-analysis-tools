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

using NtCoreLib.Ndr.Marshal;
using NtCoreLib.Ndr.Rpc;
using System;
using System.Collections.Generic;

namespace NtCoreLib.Win32.Rpc.EndpointMapper;

internal class RpcEndpointMapperManaged : IRpcEndpointMapper
{
    private const int STATUS_NO_INTERFACES = 0x16c9a0d6;

    private static RpcStringBinding GetStringBinding(RpcStringBinding search_binding)
    {
        if (search_binding == null)
        {
            if (NtObjectUtils.IsWindows)
                return new RpcStringBinding(RpcProtocolSequence.LRPC, endpoint: "epmapper");
            else
                return new RpcStringBinding(RpcProtocolSequence.Tcp, endpoint: "135");
        }
        else
        {
            return search_binding.ProtocolSequence.ToLower() switch
            {
                RpcProtocolSequence.LRPC => new RpcStringBinding(RpcProtocolSequence.LRPC, endpoint: "epmapper"),
                RpcProtocolSequence.NamedPipe => new RpcStringBinding(RpcProtocolSequence.NamedPipe, search_binding.NetworkAddress, @"\pipe\epmapper"),
                RpcProtocolSequence.Tcp => new RpcStringBinding(RpcProtocolSequence.Tcp, search_binding.NetworkAddress, "135"),
                RpcProtocolSequence.Container => new RpcStringBinding(RpcProtocolSequence.Container, search_binding.NetworkAddress, "DA32E281-383E-49A1-900A-AF3B74B90B0E"),
                RpcProtocolSequence.Http => new RpcStringBinding(RpcProtocolSequence.Http, search_binding.NetworkAddress, "593"),
                _ => null,
            };
        }
    }

    public IEnumerable<RpcEndpoint> LookupEndpoint(RpcStringBinding search_binding, RpcEndpointInquiryFlag inquiry_flag,
        RpcSyntaxIdentifier? if_id_search, RpcEndPointVersionOption version, Guid? uuid_search, bool throw_on_error = true)
    {
        const int MAX_ENTRIES = 100;
        List<RpcEndpoint> eps = new();

        RpcStringBinding string_binding = GetStringBinding(search_binding);
        if (string_binding == null)
        {
            Win32Error.RPC_S_INVALID_STRING_BINDING.ToNtException(throw_on_error);
            return Array.Empty<RpcEndpoint>();
        }

        try
        {
            using var client = new EpMapperClient();
            client.Connect(string_binding, default, null);

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
                        if (!if_id_floor.HasValue)
                            continue;

                        RpcStringBinding binding = tower.GetStringBinding();
                        if (binding == null)
                            continue;
                        UpdateBinding(binding, string_binding, entry.obj);

                        eps.Add(new RpcEndpoint(if_id_floor.Value, binding, entry.annotation, true, tower));
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
        catch
        {
            if (throw_on_error)
                throw;
        }
        return eps.AsReadOnly();
    }

    public RpcStringBinding MapEndpoint(RpcStringBinding search_binding, RpcSyntaxIdentifier if_id_search)
    {
        const int MAX_ENTRIES = 100;
        try
        {
            if (search_binding == null)
                return null;

            RpcStringBinding string_binding = GetStringBinding(search_binding);
            if (string_binding == null)
            {
                return null;
            }

            byte[] tower = RpcProtocolTower.CreateTower(if_id_search, RpcSyntaxIdentifier.DCETransferSyntax, search_binding).ToArray();

            using var client = new EpMapperClient();
            client.Connect(string_binding, default, null);

            twr_p_t tower_p = new(tower.Length, tower);

            NdrContextHandle entry_handle = NdrContextHandle.Empty;
            client.ept_map(search_binding.ObjUuid, tower_p, ref entry_handle, MAX_ENTRIES, out int num_towers, out twr_p_t?[] towers, out int status);
            try
            {
                while (status == 0)
                {
                    foreach (var entry in towers)
                    {
                        if (!entry.HasValue)
                            continue;
                        if (!RpcProtocolTower.TryParse(entry.Value.tower_octet_string, out RpcProtocolTower mapped_tower))
                            continue;
                        RpcStringBinding binding = mapped_tower.GetStringBinding();
                        if (binding == null)
                            continue;
                        UpdateBinding(binding, search_binding, search_binding.ObjUuid ?? Guid.Empty);
                        return binding;
                    }
                    if (num_towers < MAX_ENTRIES)
                        break;

                    client.ept_map(search_binding.ObjUuid, tower_p, ref entry_handle, MAX_ENTRIES,
                        out num_towers, out towers, out status);
                }
            }
            finally
            {
                if (!entry_handle.IsInvalid)
                    client.ept_lookup_handle_free(ref entry_handle, out status);
            }
        }
        catch
        {
        }
        return null;
    }

    private void UpdateBinding(RpcStringBinding binding_to_update, RpcStringBinding search_binding, Guid objuuid)
    {
        if (objuuid != Guid.Empty)
        {
            binding_to_update.ObjUuid = objuuid;
        }
        switch (binding_to_update.ProtocolSequence)
        {
            case RpcProtocolSequence.Tcp:
            case RpcProtocolSequence.Udp:
            case RpcProtocolSequence.Http:
            case RpcProtocolSequence.NamedPipe:
                binding_to_update.NetworkAddress = search_binding.NetworkAddress;
                break;
        }
    }
}
