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
using System;

namespace NtApiDotNet.Win32.Rpc.EndpointMapper
{
    #region Marshal Helpers
    internal class _Marshal_Helper : NdrMarshalBuffer
    {
        public void Write_0(RPC_IF_ID_EPT p0)
        {
            WriteStruct(p0);
        }
        public void Write_2(twr_p_t p0)
        {
            WriteStruct(p0);
        }
        public void Write_3(RPC_SID_EPT p0)
        {
            WriteStruct(p0);
        }
        public void Write_4(RPC_SID_IDENTIFIER_AUTHORITY_EPT p0)
        {
            WriteStruct(p0);
        }
        public void Write_5(byte[] p0, long p1)
        {
            WriteConformantArray(p0, p1);
        }
        public void Write_6(int[] p0, long p1)
        {
            WriteConformantArray(p0, p1);
        }
        public void Write_7(byte[] p0)
        {
            WriteFixedByteArray(p0, 6);
        }
    }
    internal class _Unmarshal_Helper : NdrUnmarshalBuffer
    {
        public _Unmarshal_Helper(RpcClientResponse r) : 
                base(r.NdrBuffer, r.Handles, r.DataRepresentation)
        {
        }
        public twr_p_t Read_2()
        {
            return ReadStruct<twr_p_t>();
        }
        public RPC_SID_IDENTIFIER_AUTHORITY_EPT Read_4()
        {
            return ReadStruct<RPC_SID_IDENTIFIER_AUTHORITY_EPT>();
        }
        public byte[] Read_5()
        {
            return ReadConformantArray<byte>();
        }
        public int[] Read_6()
        {
            return ReadConformantArray<int>();
        }
        public byte[] Read_7()
        {
            return ReadFixedByteArray(6);
        }
        public ept_entry_t[] Read_8()
        {
            return ReadConformantVaryingStructArray<ept_entry_t>();
        }
        public twr_p_t?[] Read_9()
        {
            return ReadConformantVaryingStructPointerArray<twr_p_t>(true);
        }
        public twr_p_t?[] Read_10()
        {
            return ReadConformantVaryingStructPointerArray<twr_p_t>(true);
        }
    }
    #endregion
    #region Complex Types
    internal struct RPC_IF_ID_EPT : INdrStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            Marshal((_Marshal_Helper)m);
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteGuid(Uuid);
            m.WriteInt16(VersMajor);
            m.WriteInt16(VersMinor);
        }
        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            Unmarshal((_Unmarshal_Helper)u);
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Uuid = u.ReadGuid();
            VersMajor = u.ReadInt16();
            VersMinor = u.ReadInt16();
        }
        int INdrStructure.GetAlignment()
        {
            return 4;
        }
        public Guid Uuid;
        public short VersMajor;
        public short VersMinor;
        public static RPC_IF_ID_EPT CreateDefault()
        {
            return new RPC_IF_ID_EPT();
        }
        public RPC_IF_ID_EPT(Guid uuid, short versmajor, short versminor)
        {
            Uuid = uuid;
            VersMajor = versmajor;
            VersMinor = versminor;
        }
    }
    internal struct ept_entry_t : INdrStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            Marshal((_Marshal_Helper)m);
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteGuid(obj);
            m.WriteEmbeddedPointer(tower, new Action<twr_p_t>(m.Write_2));
            m.WriteVaryingAnsiString(RpcUtils.CheckNull(annotation, "Member18"));
        }
        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            Unmarshal((_Unmarshal_Helper)u);
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            obj = u.ReadGuid();
            tower = u.ReadEmbeddedPointer(new Func<twr_p_t>(u.Read_2), true);
            annotation = u.ReadVaryingAnsiString();
        }
        int INdrStructure.GetAlignment()
        {
            return 4;
        }
        public Guid obj;
        public NdrEmbeddedPointer<twr_p_t> tower;
        public string annotation;
        public static ept_entry_t CreateDefault()
        {
            return new ept_entry_t();
        }
        public ept_entry_t(Guid obj, twr_p_t? tower, string annotation)
        {
            this.obj = obj;
            this.tower = tower;
            this.annotation = annotation;
        }
    }
    internal struct twr_p_t : INdrConformantStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            Marshal((_Marshal_Helper)m);
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt32(tower_length);
            m.Write_5(RpcUtils.CheckNull(tower_octet_string, "Member4"), tower_length);
        }
        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            Unmarshal((_Unmarshal_Helper)u);
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            tower_length = u.ReadInt32();
            tower_octet_string = u.Read_5();
        }
        int INdrConformantStructure.GetConformantDimensions()
        {
            return 1;
        }
        int INdrStructure.GetAlignment()
        {
            return 4;
        }
        public int tower_length;
        public byte[] tower_octet_string;
        public static twr_p_t CreateDefault()
        {
            twr_p_t ret = new twr_p_t();
            ret.tower_octet_string = new byte[0];
            return ret;
        }
        public twr_p_t(int tower_length, byte[] tower_octet_string)
        {
            this.tower_length = tower_length;
            this.tower_octet_string = tower_octet_string;
        }
    }
    internal struct RPC_SID_EPT : INdrConformantStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            Marshal((_Marshal_Helper)m);
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteByte(Revision);
            m.WriteByte(SubAuthorityCount);
            m.Write_4(IdentifierAuthority);
            m.Write_6(RpcUtils.CheckNull(SubAuthority, "Member8"), SubAuthorityCount);
        }
        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            Unmarshal((_Unmarshal_Helper)u);
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Revision = u.ReadByte();
            SubAuthorityCount = u.ReadByte();
            IdentifierAuthority = u.Read_4();
            SubAuthority = u.Read_6();
        }
        int INdrConformantStructure.GetConformantDimensions()
        {
            return 1;
        }
        int INdrStructure.GetAlignment()
        {
            return 4;
        }
        public byte Revision;
        public byte SubAuthorityCount;
        public RPC_SID_IDENTIFIER_AUTHORITY_EPT IdentifierAuthority;
        public int[] SubAuthority;
        public static RPC_SID_EPT CreateDefault()
        {
            RPC_SID_EPT ret = new RPC_SID_EPT();
            ret.SubAuthority = new int[0];
            return ret;
        }
        public RPC_SID_EPT(byte revision, byte sub_authority_count, RPC_SID_IDENTIFIER_AUTHORITY_EPT identifier_authority, int[] sub_authority)
        {
            Revision = revision;
            SubAuthorityCount = sub_authority_count;
            IdentifierAuthority = identifier_authority;
            SubAuthority = sub_authority;
        }
    }
    internal struct RPC_SID_IDENTIFIER_AUTHORITY_EPT : INdrStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            Marshal((_Marshal_Helper)m);
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.Write_7(RpcUtils.CheckNull(Value, "Member0"));
        }
        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            Unmarshal((_Unmarshal_Helper)u);
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Value = u.Read_7();
        }
        int INdrStructure.GetAlignment()
        {
            return 1;
        }
        public byte[] Value;
        public static RPC_SID_IDENTIFIER_AUTHORITY_EPT CreateDefault()
        {
            RPC_SID_IDENTIFIER_AUTHORITY_EPT ret = new RPC_SID_IDENTIFIER_AUTHORITY_EPT();
            ret.Value = new byte[6];
            return ret;
        }
        public RPC_SID_IDENTIFIER_AUTHORITY_EPT(byte[] value)
        {
            this.Value = value;
        }
    }
    #endregion
    #region Client Implementation
    internal sealed class EpMapperClient : RpcClientBase
    {
        public EpMapperClient() : 
                base("e1af8308-5d1f-11c9-91a4-08002b14a0fa", 3, 0)
        {
        }
        private _Unmarshal_Helper SendReceive(int p, _Marshal_Helper m)
        {
            return new _Unmarshal_Helper(SendReceive(p, m.DataRepresentation, m.ToArray(), m.Handles));
        }
        public void ept_lookup(int inquiry_type, Guid? obj, RPC_IF_ID_EPT? Ifid, 
            int vers_option, ref NdrContextHandle entry_handle, 
            int max_ents, out int num_ents, out ept_entry_t[] entries, out int status)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteInt32(inquiry_type);
            m.WriteReferent(obj, new Action<Guid>(m.WriteGuid));
            m.WriteReferent(Ifid, new Action<RPC_IF_ID_EPT>(m.Write_0));
            m.WriteInt32(vers_option);
            m.WriteContextHandle(entry_handle);
            m.WriteInt32(max_ents);
            _Unmarshal_Helper u = SendReceive(2, m);
            entry_handle = u.ReadContextHandle();
            num_ents = u.ReadInt32();
            entries = u.Read_8();
            status = u.ReadInt32();
        }
        // async
        public void ept_map(Guid? obj, twr_p_t? map_tower, ref NdrContextHandle entry_handle, int max_towers, out int num_towers, out twr_p_t?[] ITowers, out int status)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteReferent(obj, new Action<Guid>(m.WriteGuid));
            m.WriteReferent(map_tower, new Action<twr_p_t>(m.Write_2));
            m.WriteContextHandle(entry_handle);
            m.WriteInt32(max_towers);
            _Unmarshal_Helper u = SendReceive(3, m);
            entry_handle = u.ReadContextHandle();
            num_towers = u.ReadInt32();
            ITowers = u.Read_9();
            status = u.ReadInt32();
        }
        public void ept_lookup_handle_free(ref NdrContextHandle entry_handle, out int status)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteContextHandle(entry_handle);
            _Unmarshal_Helper u = SendReceive(4, m);
            entry_handle = u.ReadContextHandle();
            status = u.ReadInt32();
        }
        // async
        public void ept_map_auth(Guid obj, twr_p_t map_tower, RPC_SID_EPT? sid, ref NdrContextHandle entry_handle, int max_towers, out int num_towers, out twr_p_t?[] ITowers, out int status)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteGuid(obj);
            m.Write_2(map_tower);
            m.WriteReferent(sid, new Action<RPC_SID_EPT>(m.Write_3));
            m.WriteContextHandle(entry_handle);
            m.WriteInt32(max_towers);
            _Unmarshal_Helper u = SendReceive(7, m);
            entry_handle = u.ReadContextHandle();
            num_towers = u.ReadInt32();
            ITowers = u.Read_10();
            status = u.ReadInt32();
        }
        // async
        public void ept_map_auth_async(Guid obj, twr_p_t map_tower, RPC_SID_EPT? sid, ref NdrContextHandle entry_handle, int max_towers, out int num_towers, out twr_p_t?[] ITowers, out int status)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteGuid(obj);
            m.Write_2(map_tower);
            m.WriteReferent(sid, new Action<RPC_SID_EPT>(m.Write_3));
            m.WriteContextHandle(entry_handle);
            m.WriteInt32(max_towers);
            _Unmarshal_Helper u = SendReceive(8, m);
            entry_handle = u.ReadContextHandle();
            num_towers = u.ReadInt32();
            ITowers = u.Read_10();
            status = u.ReadInt32();
        }
    }
    #endregion
}

