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

using NtCoreLib.Ndr.Marshal;
using NtCoreLib.Ndr.Rpc;
using NtCoreLib.Win32.Rpc.Client;
using NtCoreLib.Win32.Rpc.EndpointMapper;
using NtCoreLib.Win32.Rpc.Transport;
using System;
using System.Linq;

namespace NtCoreLib.Win32.Rpc.Management;

internal class RpcManagementInterfaceClientManaged : IRpcManagementInterface
{
    #region Marshal Helpers
    private sealed class _Marshal_Helper : NdrMarshalBuffer
    {
        public _Marshal_Helper()
        {
        }
        public void Write_1(RPC_IF_ID p0)
        {
            WriteStruct(p0);
        }
        public void Write_2(RPC_IF_ID?[] p0, long p1)
        {
            WriteConformantStructPointerArray(p0, p1);
        }
    }
    private sealed class _Unmarshal_Helper : NdrUnmarshalBufferDelegator
    {
        public _Unmarshal_Helper(INdrUnmarshalBuffer r) :
                base(r)
        {
        }
        public rpc_if_id_vector_t Read_0()
        {
            return ReadStruct<rpc_if_id_vector_t>();
        }
        public RPC_IF_ID?[] Read_2()
        {
            return ReadConformantStructPointerArray<RPC_IF_ID>(false);
        }
        public int[] Read_3()
        {
            return ReadConformantArray<int>();
        }
    }
    #endregion
    #region Complex Types
    public struct rpc_if_id_vector_t : INdrConformantStructure
    {
        void INdrStructure.Marshal(INdrMarshalBuffer m)
        {
            throw new NotImplementedException();
        }
        void INdrStructure.Unmarshal(INdrUnmarshalBuffer u)
        {
            Unmarshal(new _Unmarshal_Helper(u));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Count = u.ReadInt32();
            IfId = u.Read_2();
        }
        int INdrConformantStructure.GetConformantDimensions()
        {
            return 1;
        }
        int INdrStructure.GetAlignment()
        {
            return 4;
        }
        public int Count;
        public RPC_IF_ID?[] IfId;
    }
    public struct RPC_IF_ID : INdrStructure
    {
        void INdrStructure.Marshal(INdrMarshalBuffer m)
        {
            throw new NotImplementedException();
        }
        void INdrStructure.Unmarshal(INdrUnmarshalBuffer u)
        {
            Uuid = u.ReadGuid();
            VersMajor = u.ReadUInt16();
            VersMinor = u.ReadUInt16();
        }
        int INdrStructure.GetAlignment()
        {
            return 4;
        }
        public Guid Uuid;
        public ushort VersMajor;
        public ushort VersMinor;
    }
    #endregion
    #region Client Implementation
    public sealed class Client : RpcClientBase
    {
        public Client() :
                base("afa8bd80-7d8a-11c9-bef4-08002b102989", 1, 0)
        {
        }
        private _Unmarshal_Helper SendReceive(int p, _Marshal_Helper m)
        {
            return new _Unmarshal_Helper(SendReceiveTransport(p, m));
        }
        public void rpc_mgmt_inq_if_ids(out rpc_if_id_vector_t? if_id_vector, out uint status)
        {
            _Marshal_Helper m = new();
            _Unmarshal_Helper u = SendReceive(0, m);
            if_id_vector = u.ReadReferentValue(u.Read_0, false);
            status = u.ReadUInt32();
        }
        public void rpc_mgmt_inq_stats(ref int count, out int[] statistics, out uint status)
        {
            _Marshal_Helper m = new();
            m.WriteInt32(count);
            _Unmarshal_Helper u = SendReceive(1, m);
            count = u.ReadInt32();
            statistics = u.Read_3();
            status = u.ReadUInt32();
        }
        public int rpc_mgmt_is_server_listening(out uint status)
        {
            _Marshal_Helper m = new();
            _Unmarshal_Helper u = SendReceive(2, m);
            status = u.ReadUInt32();
            return u.ReadInt32();
        }
        public void rpc_mgmt_stop_server_listening(out uint status)
        {
            _Marshal_Helper m = new();
            _Unmarshal_Helper u = SendReceive(3, m);
            status = u.ReadUInt32();
        }
        public void rpc_mgmt_inq_princ_name(int authn_proto, int princ_name_size, out string princ_name, out uint status)
        {
            _Marshal_Helper m = new();
            m.WriteInt32(authn_proto);
            m.WriteInt32(princ_name_size);
            _Unmarshal_Helper u = SendReceive(4, m);
            princ_name = u.ReadConformantVaryingAnsiString();
            status = u.ReadUInt32();
        }
    }
    #endregion

    #region IRpcManagementClient Implementation
    private readonly RpcTransportSecurity _transport_security;
    private readonly RpcClientTransportConfiguration _config;

    public RpcManagementInterfaceClientManaged(RpcTransportSecurity transport_security, RpcClientTransportConfiguration config)
    {
        _transport_security = transport_security;
        _config = config;
    }

    private Client CreateClient(RpcStringBinding binding)
    {
        Client ret = new();
        ret.Connect(binding, _transport_security, _config);
        return ret;
    }

    public NtResult<RpcSyntaxIdentifier[]> rpc_mgmt_inq_if_ids(RpcStringBinding binding, bool throw_on_error)
    {
        rpc_if_id_vector_t? v = null;
        uint status = 0;
        try
        {
            using var client = CreateClient(binding);
            client.rpc_mgmt_inq_if_ids(out v, out status);
        }
        catch
        {
            return new RpcSyntaxIdentifier[0].CreateResult();
        }
        Win32Error err = (Win32Error)status;
        if (err != Win32Error.SUCCESS)
            return err.CreateResultFromDosError<RpcSyntaxIdentifier[]>(throw_on_error);
        if (!v.HasValue)
            return new RpcSyntaxIdentifier[0].CreateResult();
        return v.Value.IfId.Select(i => i ?? default)
            .Select(i => new RpcSyntaxIdentifier(i.Uuid, i.VersMajor, i.VersMinor)).ToArray().CreateResult();
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

    public NtResult<string> rpc_mgmt_inq_princ_name(RpcStringBinding binding, RpcAuthenticationType authn_proto, bool throw_on_error)
    {
        string princ_name;
        uint status;
        try
        {
            using var client = CreateClient(binding);
            client.rpc_mgmt_inq_princ_name((int)authn_proto, 4096, out princ_name, out status);
        }
        catch
        {
            return Win32Error.RPC_S_SERVER_UNAVAILABLE.CreateResultFromDosError<string>(throw_on_error);
        }
        Win32Error err = (Win32Error)status;
        if (err != Win32Error.SUCCESS)
            return err.CreateResultFromDosError<string>(throw_on_error);
        return princ_name.CreateResult();
    }

    #endregion
}
