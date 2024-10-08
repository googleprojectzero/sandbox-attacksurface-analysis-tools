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
internal class _Unmarshal_HelperClaimSetMetadata : NdrUnmarshalBuffer
{
    internal _Unmarshal_HelperClaimSetMetadata(NdrPickledType pickled_type) :
            base(pickled_type)
    {
    }
    internal CLAIMS_SET_METADATA Read_0()
    {
        return ReadStruct<CLAIMS_SET_METADATA>();
    }
    internal byte[] Read_1()
    {
        return ReadConformantArray<byte>();
    }
    internal byte[] Read_2()
    {
        return ReadConformantArray<byte>();
    }
}
internal class _Marshal_HelperClaimSetMetadata : NdrMarshalBuffer
{
    internal void Write_0(CLAIMS_SET_METADATA p0)
    {
        WriteStruct(p0);
    }
    internal void Write_1(byte[] p0, long p1)
    {
        WriteConformantArray(p0, p1);
    }
    internal void Write_2(byte[] p0, long p1)
    {
        WriteConformantArray(p0, p1);
    }
}
#endregion
#region Complex Types
internal struct CLAIMS_SET_METADATA : INdrStructure
{
    void INdrStructure.Marshal(INdrMarshalBuffer m)
    {
        Marshal((_Marshal_HelperClaimSetMetadata)m);
    }
    private void Marshal(_Marshal_HelperClaimSetMetadata m)
    {
        m.WriteInt32(ulClaimsSetSize);
        m.WriteEmbeddedPointer(ClaimsSet, new Action<byte[], long>(m.Write_1), ulClaimsSetSize);
        m.WriteEnum16(usCompressionFormat);
        m.WriteInt32(ulUncompressedClaimsSetSize);
        m.WriteInt16(usReservedType);
        m.WriteInt32(ulReservedFieldSize);
        m.WriteEmbeddedPointer(ReservedField, new Action<byte[], long>(m.Write_2), ulReservedFieldSize);
    }
    void INdrStructure.Unmarshal(INdrUnmarshalBuffer u)
    {
        Unmarshal((_Unmarshal_HelperClaimSetMetadata)u);
    }
    private void Unmarshal(_Unmarshal_HelperClaimSetMetadata u)
    {
        ulClaimsSetSize = u.ReadInt32();
        ClaimsSet = u.ReadEmbeddedPointer(u.Read_1, false);
        usCompressionFormat = u.ReadEnum16();
        ulUncompressedClaimsSetSize = u.ReadInt32();
        usReservedType = u.ReadInt16();
        ulReservedFieldSize = u.ReadInt32();
        ReservedField = u.ReadEmbeddedPointer(u.Read_2, false);
    }
    int INdrStructure.GetAlignment()
    {
        return 4;
    }
    internal int ulClaimsSetSize;
    internal NdrEmbeddedPointer<byte[]> ClaimsSet;
    internal NdrEnum16 usCompressionFormat;
    internal int ulUncompressedClaimsSetSize;
    internal short usReservedType;
    internal int ulReservedFieldSize;
    internal NdrEmbeddedPointer<byte[]> ReservedField;
}
#endregion
#region Complex Type Encoders

internal static class ClaimSetMetadataParser
{
    internal static CLAIMS_SET_METADATA? Decode(NdrPickledType pickled_type)
    {
        var u = new _Unmarshal_HelperClaimSetMetadata(pickled_type);
        return u.ReadReferentValue(u.Read_0, false);
    }

    internal  static NdrPickledType Encode(CLAIMS_SET_METADATA? o)
    {
        var m = new _Marshal_HelperClaimSetMetadata();
        m.WriteReferent(o, m.Write_0);
        return m.ToPickledType();
    }
}
#endregion

