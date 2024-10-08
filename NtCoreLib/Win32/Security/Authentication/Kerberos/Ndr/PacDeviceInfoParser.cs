//  Copyright 2020 Google Inc. All Rights Reserved.
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
using NtCoreLib.Security.Authorization;
using NtCoreLib.Security.Token;
using System.Linq;

namespace NtCoreLib.Win32.Security.Authentication.Kerberos.Ndr;

#region Marshal Helpers
internal class _Unmarshal_HelperDeviceInfo : NdrUnmarshalBuffer
{
    internal _Unmarshal_HelperDeviceInfo(NdrPickledType pickled_type) : 
            base(pickled_type)
    {
    }
    internal PAC_DEVICE_INFO Read_0()
    {
        return ReadStruct<PAC_DEVICE_INFO>();
    }
    internal RPC_SID_DEVICE Read_1()
    {
        return ReadStruct<RPC_SID_DEVICE>();
    }
    internal RPC_SID_IDENTIFIER_AUTHORITY_DEVICE Read_2()
    {
        return ReadStruct<RPC_SID_IDENTIFIER_AUTHORITY_DEVICE>();
    }
    internal GROUP_MEMBERSHIP_DEVICE Read_3()
    {
        return ReadStruct<GROUP_MEMBERSHIP_DEVICE>();
    }
    internal KERB_SID_AND_ATTRIBUTES_DEVICE Read_4()
    {
        return ReadStruct<KERB_SID_AND_ATTRIBUTES_DEVICE>();
    }
    internal DOMAIN_GROUP_MEMBERSHIP Read_5()
    {
        return ReadStruct<DOMAIN_GROUP_MEMBERSHIP>();
    }
    internal GROUP_MEMBERSHIP_DEVICE[] Read_6()
    {
        return ReadConformantStructArray<GROUP_MEMBERSHIP_DEVICE>();
    }
    internal KERB_SID_AND_ATTRIBUTES_DEVICE[] Read_7()
    {
        return ReadConformantStructArray<KERB_SID_AND_ATTRIBUTES_DEVICE>();
    }
    internal DOMAIN_GROUP_MEMBERSHIP[] Read_8()
    {
        return ReadConformantStructArray<DOMAIN_GROUP_MEMBERSHIP>();
    }
    internal int[] Read_9()
    {
        return ReadConformantArray<int>();
    }
    internal byte[] Read_10()
    {
        return ReadFixedByteArray(6);
    }
    internal GROUP_MEMBERSHIP_DEVICE[] Read_11()
    {
        return ReadConformantStructArray<GROUP_MEMBERSHIP_DEVICE>();
    }
}
internal class _Marshal_HelperDeviceInfo : NdrMarshalBuffer
{
    internal void Write_0(PAC_DEVICE_INFO p0)
    {
        WriteStruct(p0);
    }
    internal void Write_1(RPC_SID_DEVICE p0)
    {
        WriteStruct(p0);
    }
    internal void Write_2(RPC_SID_IDENTIFIER_AUTHORITY_DEVICE p0)
    {
        WriteStruct(p0);
    }
    internal void Write_3(GROUP_MEMBERSHIP_DEVICE p0)
    {
        WriteStruct(p0);
    }
    internal void Write_4(KERB_SID_AND_ATTRIBUTES_DEVICE p0)
    {
        WriteStruct(p0);
    }
    internal void Write_5(DOMAIN_GROUP_MEMBERSHIP p0)
    {
        WriteStruct(p0);
    }
    internal void Write_6(GROUP_MEMBERSHIP_DEVICE[] p0, long p1)
    {
        WriteConformantStructArray(p0, p1);
    }
    internal void Write_7(KERB_SID_AND_ATTRIBUTES_DEVICE[] p0, long p1)
    {
        WriteConformantStructArray(p0, p1);
    }
    internal void Write_8(DOMAIN_GROUP_MEMBERSHIP[] p0, long p1)
    {
        WriteConformantStructArray(p0, p1);
    }
    internal void Write_9(int[] p0, long p1)
    {
        WriteConformantArray(p0, p1);
    }
    internal void Write_10(byte[] p0)
    {
        WriteFixedByteArray(p0, 6);
    }
    internal void Write_11(GROUP_MEMBERSHIP_DEVICE[] p0, long p1)
    {
        WriteConformantStructArray(p0, p1);
    }
}
#endregion
#region Complex Types
internal struct PAC_DEVICE_INFO : INdrStructure
{
    void INdrStructure.Marshal(INdrMarshalBuffer m)
    {
        Marshal((_Marshal_HelperDeviceInfo)m);
    }
    private void Marshal(_Marshal_HelperDeviceInfo m)
    {
        m.WriteInt32(UserId);
        m.WriteInt32(PrimaryGroupId);
        m.WriteEmbeddedPointer(AccountDomainId, m.Write_1);
        m.WriteInt32(AccountGroupCount);
        m.WriteEmbeddedPointer(AccountGroupIds, new System.Action<GROUP_MEMBERSHIP_DEVICE[], long>(m.Write_6), AccountGroupCount);
        m.WriteInt32(SidCount);
        m.WriteEmbeddedPointer(ExtraSids, new System.Action<KERB_SID_AND_ATTRIBUTES_DEVICE[], long>(m.Write_7), SidCount);
        m.WriteInt32(DomainGroupCount);
        m.WriteEmbeddedPointer(DomainGroup, new System.Action<DOMAIN_GROUP_MEMBERSHIP[], long>(m.Write_8), DomainGroupCount);
    }
    void INdrStructure.Unmarshal(INdrUnmarshalBuffer u)
    {
        Unmarshal((_Unmarshal_HelperDeviceInfo)u);
    }
    private void Unmarshal(_Unmarshal_HelperDeviceInfo u)
    {
        UserId = u.ReadInt32();
        PrimaryGroupId = u.ReadInt32();
        AccountDomainId = u.ReadEmbeddedPointer(new System.Func<RPC_SID_DEVICE>(u.Read_1), false);
        AccountGroupCount = u.ReadInt32();
        AccountGroupIds = u.ReadEmbeddedPointer(new System.Func<GROUP_MEMBERSHIP_DEVICE[]>(u.Read_6), false);
        SidCount = u.ReadInt32();
        ExtraSids = u.ReadEmbeddedPointer(new System.Func<KERB_SID_AND_ATTRIBUTES_DEVICE[]>(u.Read_7), false);
        DomainGroupCount = u.ReadInt32();
        DomainGroup = u.ReadEmbeddedPointer(new System.Func<DOMAIN_GROUP_MEMBERSHIP[]>(u.Read_8), false);
    }
    int INdrStructure.GetAlignment()
    {
        return 4;
    }
    internal int UserId;
    internal int PrimaryGroupId;
    internal NdrEmbeddedPointer<RPC_SID_DEVICE> AccountDomainId;
    internal int AccountGroupCount;
    internal NdrEmbeddedPointer<GROUP_MEMBERSHIP_DEVICE[]> AccountGroupIds;
    internal int SidCount;
    internal NdrEmbeddedPointer<KERB_SID_AND_ATTRIBUTES_DEVICE[]> ExtraSids;
    internal int DomainGroupCount;
    internal NdrEmbeddedPointer<DOMAIN_GROUP_MEMBERSHIP[]> DomainGroup;
}
internal struct RPC_SID_DEVICE : INdrConformantStructure
{
    void INdrStructure.Marshal(INdrMarshalBuffer m)
    {
        Marshal((_Marshal_HelperDeviceInfo)m);
    }
    private void Marshal(_Marshal_HelperDeviceInfo m)
    {
        m.WriteByte(Revision);
        m.WriteByte(SubAuthorityCount);
        m.Write_2(IdentifierAuthority);
        m.Write_9(NdrMarshalUtils.CheckNull(SubAuthority, "SubAuthority"), SubAuthorityCount);
    }
    void INdrStructure.Unmarshal(INdrUnmarshalBuffer u)
    {
        Unmarshal((_Unmarshal_HelperDeviceInfo)u);
    }
    private void Unmarshal(_Unmarshal_HelperDeviceInfo u)
    {
        Revision = u.ReadByte();
        SubAuthorityCount = u.ReadByte();
        IdentifierAuthority = u.Read_2();
        SubAuthority = u.Read_9();
    }
    int INdrConformantStructure.GetConformantDimensions()
    {
        return 1;
    }
    int INdrStructure.GetAlignment()
    {
        return 4;
    }
    internal Sid ToSid()
    {
        return new Sid(new SidIdentifierAuthority(IdentifierAuthority.Value),
            SubAuthority.Select(r => (uint)r).ToArray());
    }
    internal RPC_SID_DEVICE(Sid sid)
    {
        Revision = 1;
        SubAuthorityCount = (byte)sid.SubAuthorities.Count;
        IdentifierAuthority = new RPC_SID_IDENTIFIER_AUTHORITY_DEVICE(sid.Authority);
        SubAuthority = sid.SubAuthorities.Select(r => (int)r).ToArray();
    }
    internal byte Revision;
    internal byte SubAuthorityCount;
    internal RPC_SID_IDENTIFIER_AUTHORITY_DEVICE IdentifierAuthority;
    internal int[] SubAuthority;
}
internal struct RPC_SID_IDENTIFIER_AUTHORITY_DEVICE : INdrStructure
{
    void INdrStructure.Marshal(INdrMarshalBuffer m)
    {
        Marshal((_Marshal_HelperDeviceInfo)m);
    }
    private void Marshal(_Marshal_HelperDeviceInfo m)
    {
        m.Write_10(NdrMarshalUtils.CheckNull(Value, "Value"));
    }
    void INdrStructure.Unmarshal(INdrUnmarshalBuffer u)
    {
        Unmarshal((_Unmarshal_HelperDeviceInfo)u);
    }
    private void Unmarshal(_Unmarshal_HelperDeviceInfo u)
    {
        Value = u.Read_10();
    }
    int INdrStructure.GetAlignment()
    {
        return 1;
    }
    internal RPC_SID_IDENTIFIER_AUTHORITY_DEVICE(SidIdentifierAuthority id)
    {
        Value = id.Value;
    }
    internal byte[] Value;
}
internal struct GROUP_MEMBERSHIP_DEVICE : INdrStructure
{
    void INdrStructure.Marshal(INdrMarshalBuffer m)
    {
        Marshal((_Marshal_HelperDeviceInfo)m);
    }
    private void Marshal(_Marshal_HelperDeviceInfo m)
    {
        m.WriteInt32(RelativeId);
        m.WriteInt32(Attributes);
    }
    void INdrStructure.Unmarshal(INdrUnmarshalBuffer u)
    {
        Unmarshal((_Unmarshal_HelperDeviceInfo)u);
    }
    private void Unmarshal(_Unmarshal_HelperDeviceInfo u)
    {
        RelativeId = u.ReadInt32();
        Attributes = u.ReadInt32();
    }
    int INdrStructure.GetAlignment()
    {
        return 4;
    }
    internal int RelativeId;
    internal int Attributes;
}
internal struct KERB_SID_AND_ATTRIBUTES_DEVICE : INdrStructure
{
    void INdrStructure.Marshal(INdrMarshalBuffer m)
    {
        Marshal((_Marshal_HelperDeviceInfo)m);
    }
    private void Marshal(_Marshal_HelperDeviceInfo m)
    {
        m.WriteEmbeddedPointer(Sid, new System.Action<RPC_SID_DEVICE>(m.Write_1));
        m.WriteInt32(Attributes);
    }
    void INdrStructure.Unmarshal(INdrUnmarshalBuffer u)
    {
        Unmarshal((_Unmarshal_HelperDeviceInfo)u);
    }
    private void Unmarshal(_Unmarshal_HelperDeviceInfo u)
    {
        Sid = u.ReadEmbeddedPointer(new System.Func<RPC_SID_DEVICE>(u.Read_1), false);
        Attributes = u.ReadInt32();
    }
    int INdrStructure.GetAlignment()
    {
        return 4;
    }
    internal NdrEmbeddedPointer<RPC_SID_DEVICE> Sid;
    internal int Attributes;

    internal static UserGroup ToGroup(KERB_SID_AND_ATTRIBUTES_DEVICE s)
    {
        return new UserGroup(s.Sid.GetValue().ToSid(), (GroupAttributes)s.Attributes);
    }

    internal static KERB_SID_AND_ATTRIBUTES_DEVICE ToStruct(UserGroup group)
    {
        return new KERB_SID_AND_ATTRIBUTES_DEVICE()
        {
            Sid = new RPC_SID_DEVICE(group.Sid),
            Attributes = (int)group.Attributes
        };
    }
}
internal struct DOMAIN_GROUP_MEMBERSHIP : INdrStructure
{
    void INdrStructure.Marshal(INdrMarshalBuffer m)
    {
        Marshal((_Marshal_HelperDeviceInfo)m);
    }
    private void Marshal(_Marshal_HelperDeviceInfo m)
    {
        m.WriteEmbeddedPointer(DomainId, new System.Action<RPC_SID_DEVICE>(m.Write_1));
        m.WriteInt32(GroupCount);
        m.WriteEmbeddedPointer(GroupIds, new System.Action<GROUP_MEMBERSHIP_DEVICE[], long>(m.Write_11), GroupCount);
    }
    void INdrStructure.Unmarshal(INdrUnmarshalBuffer u)
    {
        Unmarshal((_Unmarshal_HelperDeviceInfo)u);
    }
    private void Unmarshal(_Unmarshal_HelperDeviceInfo u)
    {
        DomainId = u.ReadEmbeddedPointer(new System.Func<RPC_SID_DEVICE>(u.Read_1), false);
        GroupCount = u.ReadInt32();
        GroupIds = u.ReadEmbeddedPointer(new System.Func<GROUP_MEMBERSHIP_DEVICE[]>(u.Read_11), false);
    }
    int INdrStructure.GetAlignment()
    {
        return 4;
    }
    internal NdrEmbeddedPointer<RPC_SID_DEVICE> DomainId;
    internal int GroupCount;
    internal NdrEmbeddedPointer<GROUP_MEMBERSHIP_DEVICE[]> GroupIds;
}
#endregion
#region Complex Type Encoders
internal static class PacDeviceInfoParser
{
    internal static PAC_DEVICE_INFO? Decode(NdrPickledType pickled_type)
    {
        _Unmarshal_HelperDeviceInfo u = new(pickled_type);
        PAC_DEVICE_INFO? v;
        v = u.ReadReferentValue(new System.Func<PAC_DEVICE_INFO>(u.Read_0), false);
        return v;
    }
    internal static NdrPickledType Encode(PAC_DEVICE_INFO? o)
    {
        _Marshal_HelperDeviceInfo m = new();
        m.WriteReferent(o, new System.Action<PAC_DEVICE_INFO>(m.Write_0));
        return m.ToPickledType();
    }
}
#endregion

