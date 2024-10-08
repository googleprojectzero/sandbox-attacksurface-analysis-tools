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
using System;

namespace NtCoreLib.Win32.Security.Authentication.Kerberos.Ndr;

#region Marshal Helpers
internal class _Unmarshal_HelperClaimSet : NdrUnmarshalBuffer
{
    internal _Unmarshal_HelperClaimSet(NdrPickledType pickled_type) :
            base(pickled_type)
    {
    }
    internal CLAIMS_SET Read_0()
    {
        return ReadStruct<CLAIMS_SET>();
    }
    internal CLAIMS_ARRAY Read_1()
    {
        return ReadStruct<CLAIMS_ARRAY>();
    }
    internal CLAIM_ENTRY Read_2()
    {
        return ReadStruct<CLAIM_ENTRY>();
    }
    internal CLAIM_ENTRY_VALUE Read_3()
    {
        return ReadStruct<CLAIM_ENTRY_VALUE>();
    }
    internal CLAIM_TYPE_INT64 Read_4()
    {
        return ReadStruct<CLAIM_TYPE_INT64>();
    }
    internal CLAIM_TYPE_UINT64 Read_5()
    {
        return ReadStruct<CLAIM_TYPE_UINT64>();
    }
    internal CLAIM_TYPE_STRING Read_6()
    {
        return ReadStruct<CLAIM_TYPE_STRING>();
    }
    internal CLAIM_TYPE_BOOLEAN Read_7()
    {
        return ReadStruct<CLAIM_TYPE_BOOLEAN>();
    }
    internal CLAIMS_ARRAY[] Read_8()
    {
        return ReadConformantStructArray<CLAIMS_ARRAY>();
    }
    internal byte[] Read_9()
    {
        return ReadConformantArray<byte>();
    }
    internal CLAIM_ENTRY[] Read_10()
    {
        return ReadConformantStructArray<CLAIM_ENTRY>();
    }
    internal long[] Read_11()
    {
        return ReadConformantArray<long>();
    }
    internal string[] Read_12()
    {
        return ReadConformantStringArray(ReadConformantVaryingString);
    }
}
internal class _Marshal_HelperClaimSet : NdrMarshalBuffer
{
    internal void Write_0(CLAIMS_SET p0)
    {
        WriteStruct(p0);
    }
    internal void Write_1(CLAIMS_ARRAY p0)
    {
        WriteStruct(p0);
    }
    internal void Write_2(CLAIM_ENTRY p0)
    {
        WriteStruct(p0);
    }
    internal void Write_3(CLAIM_ENTRY_VALUE p0, long p1)
    {
        WriteUnion(p0, p1);
    }
    internal void Write_4(CLAIM_TYPE_INT64 p0)
    {
        WriteStruct(p0);
    }
    internal void Write_5(CLAIM_TYPE_UINT64 p0)
    {
        WriteStruct(p0);
    }
    internal void Write_6(CLAIM_TYPE_STRING p0)
    {
        WriteStruct(p0);
    }
    internal void Write_7(CLAIM_TYPE_BOOLEAN p0)
    {
        WriteStruct(p0);
    }
    internal void Write_8(CLAIMS_ARRAY[] p0, long p1)
    {
        WriteConformantStructArray(p0, p1);
    }
    internal void Write_9(byte[] p0, long p1)
    {
        WriteConformantArray(p0, p1);
    }
    internal void Write_10(CLAIM_ENTRY[] p0, long p1)
    {
        WriteConformantStructArray(p0, p1);
    }
    internal void Write_11(long[] p0, long p1)
    {
        WriteConformantArray(p0, p1);
    }
    internal void Write_12(string[] p0, long p1)
    {
        WriteConformantStringArray(p0, new Action<string>(WriteTerminatedString), p1);
    }
}
#endregion
#region Complex Types
internal struct CLAIMS_SET : INdrStructure
{
    void INdrStructure.Marshal(INdrMarshalBuffer m)
    {
        Marshal((_Marshal_HelperClaimSet)m);
    }
    private void Marshal(_Marshal_HelperClaimSet m)
    {
        m.WriteInt32(ulClaimsArrayCount);
        m.WriteEmbeddedPointer(ClaimsArrays, new Action<CLAIMS_ARRAY[], long>(m.Write_8), ulClaimsArrayCount);
        m.WriteInt16(usReservedType);
        m.WriteInt32(ulReservedFieldSize);
        m.WriteEmbeddedPointer(ReservedField, new Action<byte[], long>(m.Write_9), ulReservedFieldSize);
    }
    void INdrStructure.Unmarshal(INdrUnmarshalBuffer u)
    {
        Unmarshal((_Unmarshal_HelperClaimSet)u);
    }
    private void Unmarshal(_Unmarshal_HelperClaimSet u)
    {
        ulClaimsArrayCount = u.ReadInt32();
        ClaimsArrays = u.ReadEmbeddedPointer(u.Read_8, false);
        usReservedType = u.ReadInt16();
        ulReservedFieldSize = u.ReadInt32();
        ReservedField = u.ReadEmbeddedPointer(u.Read_9, false);
    }
    int INdrStructure.GetAlignment()
    {
        return 4;
    }
    internal int ulClaimsArrayCount;
    internal NdrEmbeddedPointer<CLAIMS_ARRAY[]> ClaimsArrays;
    internal short usReservedType;
    internal int ulReservedFieldSize;
    internal NdrEmbeddedPointer<byte[]> ReservedField;
}
internal struct CLAIMS_ARRAY : INdrStructure
{
    void INdrStructure.Marshal(INdrMarshalBuffer m)
    {
        Marshal((_Marshal_HelperClaimSet)m);
    }
    private void Marshal(_Marshal_HelperClaimSet m)
    {
        m.WriteEnum16(usClaimsSourceType);
        m.WriteInt32(ulClaimsCount);
        m.WriteEmbeddedPointer(ClaimEntries, new Action<CLAIM_ENTRY[], long>(m.Write_10), ulClaimsCount);
    }
    void INdrStructure.Unmarshal(INdrUnmarshalBuffer u)
    {
        Unmarshal((_Unmarshal_HelperClaimSet)u);
    }
    private void Unmarshal(_Unmarshal_HelperClaimSet u)
    {
        usClaimsSourceType = u.ReadEnum16();
        ulClaimsCount = u.ReadInt32();
        ClaimEntries = u.ReadEmbeddedPointer(new Func<CLAIM_ENTRY[]>(u.Read_10), false);
    }
    int INdrStructure.GetAlignment()
    {
        return 4;
    }
    internal NdrEnum16 usClaimsSourceType;
    internal int ulClaimsCount;
    internal NdrEmbeddedPointer<CLAIM_ENTRY[]> ClaimEntries;
}
internal struct CLAIM_ENTRY : INdrStructure
{
    void INdrStructure.Marshal(INdrMarshalBuffer m)
    {
        Marshal((_Marshal_HelperClaimSet)m);
    }
    private void Marshal(_Marshal_HelperClaimSet m)
    {
        m.WriteEmbeddedPointer(Id, m.WriteTerminatedString);
        m.WriteEnum16(ClaimType);
        m.Write_3(Values, ClaimType);
    }
    void INdrStructure.Unmarshal(INdrUnmarshalBuffer u)
    {
        Unmarshal((_Unmarshal_HelperClaimSet)u);
    }
    private void Unmarshal(_Unmarshal_HelperClaimSet u)
    {
        Id = u.ReadEmbeddedPointer(u.ReadConformantVaryingString, false);
        ClaimType = u.ReadEnum16();
        Values = u.Read_3();
    }
    int INdrStructure.GetAlignment()
    {
        return 4;
    }
    internal NdrEmbeddedPointer<string> Id;
    internal NdrEnum16 ClaimType;
    internal CLAIM_ENTRY_VALUE Values;
}
internal struct CLAIM_ENTRY_VALUE : INdrNonEncapsulatedUnion
{
    void INdrStructure.Marshal(INdrMarshalBuffer m)
    {
        throw new NotImplementedException();
    }
    void INdrNonEncapsulatedUnion.Marshal(INdrMarshalBuffer m, long l)
    {
        Selector = (NdrEnum16)l;
        Marshal((_Marshal_HelperClaimSet)m);
    }
    private void Marshal(_Marshal_HelperClaimSet m)
    {
        m.WriteEnum16(Selector);
        switch (Selector)
        {
            case 1:
                m.Write_4(ValueInt64);
                break;
            case 2:
                m.Write_5(ValueUInt64);
                break;
            case 3:
                m.Write_6(ValueString);
                break;
            case 6:
                m.Write_7(ValueBoolean);
                break;
            default:
                m.WriteEmpty(Arm_Default);
                break;
        }
    }
    void INdrStructure.Unmarshal(INdrUnmarshalBuffer u)
    {
        Unmarshal((_Unmarshal_HelperClaimSet)u);
    }
    private void Unmarshal(_Unmarshal_HelperClaimSet u)
    {
        Selector = u.ReadEnum16();
        switch (Selector)
        {
            case 1:
                ValueInt64 = u.Read_4();
                break;
            case 2:
                ValueUInt64 = u.Read_5();
                break;
            case 3:
                ValueString = u.Read_6();
                break;
            case 6:
                ValueBoolean = u.Read_7();
                break;
            default:
                Arm_Default = u.ReadEmpty();
                break;
        }
    }
    int INdrStructure.GetAlignment()
    {
        return 1;
    }
    private NdrEnum16 Selector;
    internal CLAIM_TYPE_INT64 ValueInt64;
    internal CLAIM_TYPE_UINT64 ValueUInt64;
    internal CLAIM_TYPE_STRING ValueString;
    internal CLAIM_TYPE_BOOLEAN ValueBoolean;
    internal NdrEmpty Arm_Default;
}
internal struct CLAIM_TYPE_INT64 : INdrStructure
{
    void INdrStructure.Marshal(INdrMarshalBuffer m)
    {
        Marshal((_Marshal_HelperClaimSet)m);
    }
    private void Marshal(_Marshal_HelperClaimSet m)
    {
        m.WriteInt32(ValueCount);
        m.WriteEmbeddedPointer(Int64Values, new Action<long[], long>(m.Write_11), ValueCount);
    }
    void INdrStructure.Unmarshal(INdrUnmarshalBuffer u)
    {
        Unmarshal((_Unmarshal_HelperClaimSet)u);
    }
    private void Unmarshal(_Unmarshal_HelperClaimSet u)
    {
        ValueCount = u.ReadInt32();
        Int64Values = u.ReadEmbeddedPointer(new Func<long[]>(u.Read_11), false);
    }
    int INdrStructure.GetAlignment()
    {
        return 4;
    }
    internal int ValueCount;
    internal NdrEmbeddedPointer<long[]> Int64Values;
}
internal struct CLAIM_TYPE_UINT64 : INdrStructure
{
    void INdrStructure.Marshal(INdrMarshalBuffer m)
    {
        Marshal((_Marshal_HelperClaimSet)m);
    }
    private void Marshal(_Marshal_HelperClaimSet m)
    {
        m.WriteInt32(ValueCount);
        m.WriteEmbeddedPointer(Uint64Values, new Action<long[], long>(m.Write_11), ValueCount);
    }
    void INdrStructure.Unmarshal(INdrUnmarshalBuffer u)
    {
        Unmarshal((_Unmarshal_HelperClaimSet)u);
    }
    private void Unmarshal(_Unmarshal_HelperClaimSet u)
    {
        ValueCount = u.ReadInt32();
        Uint64Values = u.ReadEmbeddedPointer(new Func<long[]>(u.Read_11), false);
    }
    int INdrStructure.GetAlignment()
    {
        return 4;
    }
    internal int ValueCount;
    internal NdrEmbeddedPointer<long[]> Uint64Values;
}
internal struct CLAIM_TYPE_STRING : INdrStructure
{
    void INdrStructure.Marshal(INdrMarshalBuffer m)
    {
        Marshal((_Marshal_HelperClaimSet)m);
    }
    private void Marshal(_Marshal_HelperClaimSet m)
    {
        m.WriteInt32(ValueCount);
        m.WriteEmbeddedPointer(StringValues, new Action<string[], long>(m.Write_12), ValueCount);
    }
    void INdrStructure.Unmarshal(INdrUnmarshalBuffer u)
    {
        Unmarshal((_Unmarshal_HelperClaimSet)u);
    }
    private void Unmarshal(_Unmarshal_HelperClaimSet u)
    {
        ValueCount = u.ReadInt32();
        StringValues = u.ReadEmbeddedPointer(new Func<string[]>(u.Read_12), false);
    }
    int INdrStructure.GetAlignment()
    {
        return 4;
    }
    internal int ValueCount;
    internal NdrEmbeddedPointer<string[]> StringValues;
}
internal struct CLAIM_TYPE_BOOLEAN : INdrStructure
{
    void INdrStructure.Marshal(INdrMarshalBuffer m)
    {
        Marshal((_Marshal_HelperClaimSet)m);
    }
    private void Marshal(_Marshal_HelperClaimSet m)
    {
        m.WriteInt32(ValueCount);
        m.WriteEmbeddedPointer(BooleanValues, new Action<long[], long>(m.Write_11), ValueCount);
    }
    void INdrStructure.Unmarshal(INdrUnmarshalBuffer u)
    {
        Unmarshal((_Unmarshal_HelperClaimSet)u);
    }
    private void Unmarshal(_Unmarshal_HelperClaimSet u)
    {
        ValueCount = u.ReadInt32();
        BooleanValues = u.ReadEmbeddedPointer(new Func<long[]>(u.Read_11), false);
    }
    int INdrStructure.GetAlignment()
    {
        return 4;
    }
    internal int ValueCount;
    internal NdrEmbeddedPointer<long[]> BooleanValues;
}
#endregion
#region Complex Type Encoders
internal static class ClaimSetParser
{
    internal static CLAIMS_SET? Decode(NdrPickledType pickled_type)
    {
        _Unmarshal_HelperClaimSet u = new(pickled_type);
        return u.ReadReferentValue(u.Read_0, false);
    }
    internal static NdrPickledType Encode(CLAIMS_SET? o)
    {
        _Marshal_HelperClaimSet m = new();
        m.WriteReferent(o, m.Write_0);
        return m.ToPickledType();
    }
}
#endregion

