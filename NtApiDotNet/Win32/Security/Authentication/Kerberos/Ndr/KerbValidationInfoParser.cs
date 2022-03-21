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

using NtApiDotNet.Ndr.Marshal;
using System;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Ndr
{
#pragma warning disable 1591

    #region Marshal Helpers
    internal class _Unmarshal_Helper : NdrUnmarshalBuffer
    {
        internal _Unmarshal_Helper(NdrPickledType pickled_type) :
                base(pickled_type)
        {
        }
        internal KERB_VALIDATION_INFO Read_0()
        {
            return ReadStruct<KERB_VALIDATION_INFO>();
        }
        internal FILETIME Read_1()
        {
            return ReadStruct<FILETIME>();
        }
        internal RPC_UNICODE_STRING Read_2()
        {
            return ReadStruct<RPC_UNICODE_STRING>();
        }
        internal USER_SESSION_KEY Read_3()
        {
            return ReadStruct<USER_SESSION_KEY>();
        }
        internal CYPHER_BLOCK Read_4()
        {
            return ReadStruct<CYPHER_BLOCK>();
        }
        internal RPC_SID Read_5()
        {
            return ReadStruct<RPC_SID>();
        }
        internal RPC_SID_IDENTIFIER_AUTHORITY Read_6()
        {
            return ReadStruct<RPC_SID_IDENTIFIER_AUTHORITY>();
        }
        internal GROUP_MEMBERSHIP[] Read_GROUP_MEMBERSHIP()
        {
            return ReadConformantStructArray<GROUP_MEMBERSHIP>();
        }
        internal int[] Read_9()
        {
            return ReadFixedPrimitiveArray<int>(2);
        }
        internal int[] Read_10()
        {
            return ReadFixedPrimitiveArray<int>(7);
        }
        internal KERB_SID_AND_ATTRIBUTES[] Read_11()
        {
            return ReadConformantStructArray<KERB_SID_AND_ATTRIBUTES>();
        }
        internal char[] Read_13()
        {
            return ReadConformantVaryingArray<char>();
        }
        internal CYPHER_BLOCK[] Read_14()
        {
            return ReadFixedStructArray<CYPHER_BLOCK>(2);
        }
        internal sbyte[] Read_15()
        {
            return ReadFixedPrimitiveArray<sbyte>(8);
        }
        internal int[] Read_16()
        {
            return ReadConformantArray<int>();
        }
        internal byte[] Read_17()
        {
            return ReadFixedByteArray(6);
        }
    }
    internal class _Marshal_Helper : NdrMarshalBuffer
    {
        internal void Write_0(KERB_VALIDATION_INFO p0)
        {
            WriteStruct(p0);
        }
        internal void Write_1(FILETIME p0)
        {
            WriteStruct(p0);
        }
        internal void Write_2(RPC_UNICODE_STRING p0)
        {
            WriteStruct(p0);
        }
        internal void Write_3(USER_SESSION_KEY p0)
        {
            WriteStruct(p0);
        }
        internal void Write_4(CYPHER_BLOCK p0)
        {
            WriteStruct(p0);
        }
        internal void Write_5(RPC_SID p0)
        {
            WriteStruct(p0);
        }
        internal void Write_6(RPC_SID_IDENTIFIER_AUTHORITY p0)
        {
            WriteStruct(p0);
        }
        internal void Write_GROUP_MEMBERSHIP(GROUP_MEMBERSHIP[] p0, long p1)
        {
            WriteConformantStructArray(p0, p1);
        }
        internal void Write_9(int[] p0)
        {
            WriteFixedPrimitiveArray(p0, 2);
        }
        internal void Write_10(int[] p0)
        {
            WriteFixedPrimitiveArray(p0, 7);
        }
        internal void Write_11(KERB_SID_AND_ATTRIBUTES[] p0, long p1)
        {
            WriteConformantStructArray<KERB_SID_AND_ATTRIBUTES>(p0, p1);
        }
        internal void Write_13(char[] p0, long p1, long p2)
        {
            WriteConformantVaryingArray(p0, p1, p2);
        }
        internal void Write_14(CYPHER_BLOCK[] p0)
        {
            WriteFixedStructArray(p0, 2);
        }
        internal void Write_15(sbyte[] p0)
        {
            WriteFixedPrimitiveArray(p0, 8);
        }
        internal void Write_16(int[] p0, long p1)
        {
            WriteConformantArray(p0, p1);
        }
        internal void Write_17(byte[] p0)
        {
            WriteFixedByteArray(p0, 6);
        }
    }
    #endregion
    #region Complex Types
    internal struct KERB_VALIDATION_INFO : INdrStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.Write_1(LogonTime);
            m.Write_1(LogoffTime);
            m.Write_1(KickOffTime);
            m.Write_1(PasswordLastSet);
            m.Write_1(PasswordCanChange);
            m.Write_1(PasswordMustChange);
            m.Write_2(EffectiveName);
            m.Write_2(FullName);
            m.Write_2(LogonScript);
            m.Write_2(ProfilePath);
            m.Write_2(HomeDirectory);
            m.Write_2(HomeDirectoryDrive);
            m.WriteInt16(LogonCount);
            m.WriteInt16(BadPasswordCount);
            m.WriteInt32(UserId);
            m.WriteInt32(PrimaryGroupId);
            m.WriteInt32(GroupCount);
            m.WriteEmbeddedPointer(GroupIds, new System.Action<GROUP_MEMBERSHIP[], long>(m.Write_GROUP_MEMBERSHIP), GroupCount);
            m.WriteInt32(UserFlags);
            m.Write_3(UserSessionKey);
            m.Write_2(LogonServer);
            m.Write_2(LogonDomainName);
            m.WriteEmbeddedPointer(LogonDomainId, new System.Action<RPC_SID>(m.Write_5));
            m.Write_9(Rpc.RpcUtils.CheckNull(Reserved1, "Reserved1"));
            m.WriteInt32(UserAccountControl);
            m.Write_10(Rpc.RpcUtils.CheckNull(Reserved3, "Reserved3"));
            m.WriteInt32(SidCount);
            m.WriteEmbeddedPointer(ExtraSids, new System.Action<KERB_SID_AND_ATTRIBUTES[], long>(m.Write_11), SidCount);
            m.WriteEmbeddedPointer(ResourceGroupDomainSid, new System.Action<RPC_SID>(m.Write_5));
            m.WriteInt32(ResourceGroupCount);
            m.WriteEmbeddedPointer(ResourceGroupIds, new System.Action<GROUP_MEMBERSHIP[], long>(m.Write_GROUP_MEMBERSHIP), ResourceGroupCount);
        }
        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            Unmarshal((_Unmarshal_Helper)u);
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            LogonTime = u.Read_1();
            LogoffTime = u.Read_1();
            KickOffTime = u.Read_1();
            PasswordLastSet = u.Read_1();
            PasswordCanChange = u.Read_1();
            PasswordMustChange = u.Read_1();
            EffectiveName = u.Read_2();
            FullName = u.Read_2();
            LogonScript = u.Read_2();
            ProfilePath = u.Read_2();
            HomeDirectory = u.Read_2();
            HomeDirectoryDrive = u.Read_2();
            LogonCount = u.ReadInt16();
            BadPasswordCount = u.ReadInt16();
            UserId = u.ReadInt32();
            PrimaryGroupId = u.ReadInt32();
            GroupCount = u.ReadInt32();
            GroupIds = u.ReadEmbeddedPointer(u.Read_GROUP_MEMBERSHIP, false);
            UserFlags = u.ReadInt32();
            UserSessionKey = u.Read_3();
            LogonServer = u.Read_2();
            LogonDomainName = u.Read_2();
            LogonDomainId = u.ReadEmbeddedPointer(u.Read_5, false);
            Reserved1 = u.Read_9();
            UserAccountControl = u.ReadInt32();
            Reserved3 = u.Read_10();
            SidCount = u.ReadInt32();
            ExtraSids = u.ReadEmbeddedPointer(u.Read_11, false);
            ResourceGroupDomainSid = u.ReadEmbeddedPointer(u.Read_5, false);
            ResourceGroupCount = u.ReadInt32();
            ResourceGroupIds = u.ReadEmbeddedPointer(u.Read_GROUP_MEMBERSHIP, false);
        }
        int INdrStructure.GetAlignment()
        {
            return 4;
        }
        internal FILETIME LogonTime;
        internal FILETIME LogoffTime;
        internal FILETIME KickOffTime;
        internal FILETIME PasswordLastSet;
        internal FILETIME PasswordCanChange;
        internal FILETIME PasswordMustChange;
        internal RPC_UNICODE_STRING EffectiveName;
        internal RPC_UNICODE_STRING FullName;
        internal RPC_UNICODE_STRING LogonScript;
        internal RPC_UNICODE_STRING ProfilePath;
        internal RPC_UNICODE_STRING HomeDirectory;
        internal RPC_UNICODE_STRING HomeDirectoryDrive;
        internal short LogonCount;
        internal short BadPasswordCount;
        internal int UserId;
        internal int PrimaryGroupId;
        internal int GroupCount;
        internal NdrEmbeddedPointer<GROUP_MEMBERSHIP[]> GroupIds;
        internal int UserFlags;
        internal USER_SESSION_KEY UserSessionKey;
        internal RPC_UNICODE_STRING LogonServer;
        internal RPC_UNICODE_STRING LogonDomainName;
        internal NdrEmbeddedPointer<RPC_SID> LogonDomainId;
        internal int[] Reserved1;
        internal int UserAccountControl;
        internal int[] Reserved3;
        internal int SidCount;
        internal NdrEmbeddedPointer<KERB_SID_AND_ATTRIBUTES[]> ExtraSids;
        internal NdrEmbeddedPointer<RPC_SID> ResourceGroupDomainSid;
        internal int ResourceGroupCount;
        internal NdrEmbeddedPointer<GROUP_MEMBERSHIP[]> ResourceGroupIds;
    }
    internal struct FILETIME : INdrStructure
    {
        internal FILETIME(DateTime dateTime)
        {
            var fileTime = dateTime.ToFileTimeUtc();
            LowerValue = (uint)(fileTime & 0xffffffff);
            UpperValue = (uint)((fileTime >> 32) & 0xffffffff);
        }

        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            m.WriteUInt32(LowerValue);
            m.WriteUInt32(UpperValue);
        }

        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            Unmarshal((_Unmarshal_Helper)u);
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            LowerValue = u.ReadUInt32();
            UpperValue = u.ReadUInt32();
        }
        int INdrStructure.GetAlignment()
        {
            return 4;
        }
        internal uint LowerValue;
        internal uint UpperValue;

        public DateTime ToTime()
        {
            try
            {
                return DateTime.FromFileTimeUtc((long)LowerValue | ((long)UpperValue << 32));
            }
            catch (ArgumentOutOfRangeException)
            {
                return DateTime.MaxValue;
            }
        }
    }
    internal struct GROUP_MEMBERSHIP : INdrStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            m.WriteInt32(RelativeId);
            m.WriteInt32(Attributes);
        }

        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            Unmarshal((_Unmarshal_Helper)u);
        }
        private void Unmarshal(_Unmarshal_Helper u)
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
    internal struct RPC_UNICODE_STRING : INdrStructure
    {
        public RPC_UNICODE_STRING(short Length, short MaximumLength, char[] Buffer)
        {
            this.Length = Length;
            this.MaximumLength = MaximumLength;
            this.Buffer = Buffer;
        }

        public RPC_UNICODE_STRING(string value)
        {
            this.Length = (short)(value.Length * 2);
            this.MaximumLength = this.Length;
            this.Buffer = value.ToCharArray();
        }

        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        void Marshal(_Marshal_Helper m)
        {
            m.WriteInt16(Length);
            m.WriteInt16(MaximumLength);
            m.WriteEmbeddedPointer<char[], long, long>(Buffer, new System.Action<char[], long, long>(m.Write_13), (MaximumLength / 2), (Length / 2));
        }

        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            Unmarshal((_Unmarshal_Helper)u);
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Length = u.ReadInt16();
            MaximumLength = u.ReadInt16();
            Buffer = u.ReadEmbeddedPointer(u.Read_13, false);
        }
        int INdrStructure.GetAlignment()
        {
            return 4;
        }
        internal short Length;
        internal short MaximumLength;
        internal NdrEmbeddedPointer<char[]> Buffer;
        public override string ToString()
        {
            if (Buffer == null)
                return string.Empty;
            return new string(Buffer, 0, Length / 2);
        }
    }
    internal struct USER_SESSION_KEY : INdrStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        void Marshal(_Marshal_Helper m)
        {
            m.Write_14(Rpc.RpcUtils.CheckNull(data, "data"));
        }
        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            Unmarshal((_Unmarshal_Helper)u);
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            data = u.Read_14();
        }
        int INdrStructure.GetAlignment()
        {
            return 1;
        }
        internal CYPHER_BLOCK[] data;
    }
    internal struct CYPHER_BLOCK : INdrStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        void Marshal(_Marshal_Helper m)
        {
            m.Write_15(Rpc.RpcUtils.CheckNull(data, "data"));
        }
        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            Unmarshal((_Unmarshal_Helper)u);
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            data = u.Read_15();
        }
        int INdrStructure.GetAlignment()
        {
            return 1;
        }
        internal sbyte[] data;
    }
    internal struct RPC_SID : INdrConformantStructure
    {
        public RPC_SID(Sid sid)
        {
            Revision = 1;
            SubAuthorityCount = (sbyte)sid.SubAuthorities.Count;
            IdentifierAuthority.Value = sid.Authority.Value;
            SubAuthority = (int[])(object)sid.SubAuthorities.ToArray();
        }

        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        void Marshal(_Marshal_Helper m)
        {
            m.WriteSByte(Revision);
            m.WriteSByte(SubAuthorityCount);
            m.Write_6(IdentifierAuthority);
            m.Write_16(Rpc.RpcUtils.CheckNull(SubAuthority, "SubAuthority"), SubAuthorityCount);
        }
        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            Unmarshal((_Unmarshal_Helper)u);
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Revision = u.ReadSByte();
            SubAuthorityCount = u.ReadSByte();
            IdentifierAuthority = u.Read_6();
            SubAuthority = u.Read_16();
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

        internal sbyte Revision;
        internal sbyte SubAuthorityCount;
        internal RPC_SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
        internal int[] SubAuthority;
    }
    internal struct RPC_SID_IDENTIFIER_AUTHORITY : INdrStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        void Marshal(_Marshal_Helper m)
        {
            m.Write_17(Rpc.RpcUtils.CheckNull(Value, "Value"));
        }
        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            Unmarshal((_Unmarshal_Helper)u);
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Value = u.Read_17();
        }
        int INdrStructure.GetAlignment()
        {
            return 1;
        }
        internal byte[] Value;
    }
    internal struct KERB_SID_AND_ATTRIBUTES : INdrStructure
    {
        void INdrStructure.Marshal(NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        void Marshal(_Marshal_Helper m)
        {
            m.WriteEmbeddedPointer(Sid, new System.Action<RPC_SID>(m.Write_5));
            m.WriteInt32(Attributes);
        }
        void INdrStructure.Unmarshal(NdrUnmarshalBuffer u)
        {
            Unmarshal((_Unmarshal_Helper)u);
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Sid = u.ReadEmbeddedPointer(u.Read_5, false);
            Attributes = u.ReadInt32();
        }
        int INdrStructure.GetAlignment()
        {
            return 4;
        }
        internal NdrEmbeddedPointer<RPC_SID> Sid;
        internal int Attributes;
    }
    #endregion
    #region Complex Type Encoders
    internal static class KerbValidationInfoParser
    {
        internal static KERB_VALIDATION_INFO? Decode(NdrPickledType pickled_type)
        {
            _Unmarshal_Helper u = new _Unmarshal_Helper(pickled_type);
            return u.ReadReferentValue(u.Read_0, false);
        }
        internal static byte[] Encode(KERB_VALIDATION_INFO info)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteReferent(info, new Action<KERB_VALIDATION_INFO>(m.WriteStruct));
            return m.ToPickledType().ToArray();
        }
    }
    #endregion
}