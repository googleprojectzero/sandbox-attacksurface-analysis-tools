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
using System;

namespace NtCoreLib.Win32.Security.Authentication.Kerberos.Ndr;

#region Marshal Helpers
internal class _Marshal_HelperCredData : NdrMarshalBuffer
{
    public void Write_0(PAC_CREDENTIAL_DATA p0)
    {
        WriteStruct(p0);
    }
    public void Write_2(RPC_UNICODE_STRING_CRED p0)
    {
        WriteStruct(p0);
    }
    public void Write_3(SECPKG_SUPPLEMENTAL_CRED[] p0, long p1)
    {
        WriteConformantStructArray(p0, p1);
    }
    public void Write_4(byte[] p0, long p1)
    {
        WriteConformantArray(p0, p1);
    }
    public void Write_5(char[] p0, long p1, long p2)
    {
        WriteConformantVaryingArray(p0, p1, p2);
    }
}
internal class _Unmarshal_HelperCredData : NdrUnmarshalBuffer
{
    public _Unmarshal_HelperCredData(NdrPickledType pickled_type) :
            base(pickled_type)
    {
    }
    public PAC_CREDENTIAL_DATA Read_0()
    {
        return ReadStruct<PAC_CREDENTIAL_DATA>();
    }
    public RPC_UNICODE_STRING_CRED Read_2()
    {
        return ReadStruct<RPC_UNICODE_STRING_CRED>();
    }
    public SECPKG_SUPPLEMENTAL_CRED[] Read_3()
    {
        return ReadConformantStructArray<SECPKG_SUPPLEMENTAL_CRED>();
    }
    public byte[] Read_4()
    {
        return ReadConformantArray<byte>();
    }
    public char[] Read_5()
    {
        return ReadConformantVaryingArray<char>();
    }
}
#endregion
#region Complex Types
internal struct PAC_CREDENTIAL_DATA : INdrConformantStructure
{
    void INdrStructure.Marshal(INdrMarshalBuffer m)
    {
        Marshal((_Marshal_HelperCredData)m);
    }
    private void Marshal(_Marshal_HelperCredData m)
    {
        m.WriteInt32(CredentialCount);
        m.Write_3(NdrMarshalUtils.CheckNull(Credentials, "Credentials"), CredentialCount);
    }
    void INdrStructure.Unmarshal(INdrUnmarshalBuffer u)
    {
        Unmarshal((_Unmarshal_HelperCredData)u);
    }
    private void Unmarshal(_Unmarshal_HelperCredData u)
    {
        CredentialCount = u.ReadInt32();
        Credentials = u.Read_3();
    }
    int INdrConformantStructure.GetConformantDimensions()
    {
        return 1;
    }
    int INdrStructure.GetAlignment()
    {
        return 4;
    }
    public int CredentialCount;
    public SECPKG_SUPPLEMENTAL_CRED[] Credentials;
}
internal struct SECPKG_SUPPLEMENTAL_CRED : INdrStructure
{
    void INdrStructure.Marshal(INdrMarshalBuffer m)
    {
        Marshal((_Marshal_HelperCredData)m);
    }
    private void Marshal(_Marshal_HelperCredData m)
    {
        m.Write_2(PackageName);
        m.WriteInt32(CredentialSize);
        m.WriteEmbeddedPointer(Credentials, new Action<byte[], long>(m.Write_4), CredentialSize);
    }
    void INdrStructure.Unmarshal(INdrUnmarshalBuffer u)
    {
        Unmarshal((_Unmarshal_HelperCredData)u);
    }
    private void Unmarshal(_Unmarshal_HelperCredData u)
    {
        PackageName = u.Read_2();
        CredentialSize = u.ReadInt32();
        Credentials = u.ReadEmbeddedPointer(new Func<byte[]>(u.Read_4), false);
    }
    int INdrStructure.GetAlignment()
    {
        return 4;
    }
    public RPC_UNICODE_STRING_CRED PackageName;
    public int CredentialSize;
    public NdrEmbeddedPointer<byte[]> Credentials;
}
internal struct RPC_UNICODE_STRING_CRED : INdrStructure
{
    void INdrStructure.Marshal(INdrMarshalBuffer m)
    {
        Marshal((_Marshal_HelperCredData)m);
    }
    private void Marshal(_Marshal_HelperCredData m)
    {
        m.WriteInt16(Length);
        m.WriteInt16(MaximumLength);
        m.WriteEmbeddedPointer(Buffer, new Action<char[], long, long>(m.Write_5), MaximumLength / 2, Length / 2);
    }
    void INdrStructure.Unmarshal(INdrUnmarshalBuffer u)
    {
        Unmarshal((_Unmarshal_HelperCredData)u);
    }
    private void Unmarshal(_Unmarshal_HelperCredData u)
    {
        Length = u.ReadInt16();
        MaximumLength = u.ReadInt16();
        Buffer = u.ReadEmbeddedPointer(new Func<char[]>(u.Read_5), false);
    }
    int INdrStructure.GetAlignment()
    {
        return 4;
    }
    public short Length;
    public short MaximumLength;
    public NdrEmbeddedPointer<char[]> Buffer;
    public static RPC_UNICODE_STRING_CRED CreateDefault()
    {
        return new RPC_UNICODE_STRING_CRED();
    }
    public RPC_UNICODE_STRING_CRED(short Member0, short Member2, char[] Member8)
    {
        Length = Member0;
        MaximumLength = Member2;
        Buffer = Member8;
    }
    public override string ToString()
    {
        if (Buffer == null)
            return null;
        return new string(Buffer, 0, Length / 2);
    }
}
#endregion
#region Complex Type Encoders
internal static class PacCredentialDataParser
{
    public static NdrPickledType Encode(PAC_CREDENTIAL_DATA? o)
    {
        _Marshal_HelperCredData m = new();
        m.WriteReferent(o, new Action<PAC_CREDENTIAL_DATA>(m.Write_0));
        return m.ToPickledType();
    }
    public static PAC_CREDENTIAL_DATA? Decode(NdrPickledType pickled_type)
    {
        _Unmarshal_HelperCredData u = new(pickled_type);
        PAC_CREDENTIAL_DATA? v;
        v = u.ReadReferentValue(new Func<PAC_CREDENTIAL_DATA>(u.Read_0), false);
        return v;
    }
}
#endregion
