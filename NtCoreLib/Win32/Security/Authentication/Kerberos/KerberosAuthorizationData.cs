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

using NtCoreLib.Utilities.ASN1;
using NtCoreLib.Utilities.ASN1.Builder;
using NtCoreLib.Win32.Security.Authentication.Kerberos.Builder;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NtCoreLib.Win32.Security.Authentication.Kerberos;

/// <summary>
/// Class representing Kerberos authentication data.
/// </summary>
public abstract class KerberosAuthorizationData : IDERObject
{
    /// <summary>
    /// Type of authentication data.
    /// </summary>
    public KerberosAuthorizationDataType DataType { get; }

    /// <summary>
    /// Convert the authorization data into a builder.
    /// </summary>
    /// <returns>The authorization builder.</returns>
    public virtual KerberosAuthorizationDataBuilder ToBuilder()
    {
        return new KerberosAuthorizationDataRawBuilder(DataType, GetData());
    }

    private protected KerberosAuthorizationData(KerberosAuthorizationDataType type)
    {
        DataType = type;
    }

    internal static KerberosAuthorizationData Parse(DERValue value)
    {
        if (!value.CheckSequence())
            throw new InvalidDataException();
        KerberosAuthorizationDataType type = 0;
        byte[] data = null;
        foreach (var next in value.Children)
        {
            if (next.Type != DERTagType.ContextSpecific)
                throw new InvalidDataException();
            switch (next.Tag)
            {
                case 0:
                    type = (KerberosAuthorizationDataType)next.ReadChildInteger();
                    break;
                case 1:
                    data = next.ReadChildOctetString();
                    break;
                default:
                    throw new InvalidDataException();
            }
        }

        if (type == 0 || data == null)
            throw new InvalidDataException();

        if (type == KerberosAuthorizationDataType.AD_IF_RELEVANT)
        {
            if (KerberosAuthorizationDataIfRelevant.Parse(data, 
                out KerberosAuthorizationDataIfRelevant entry))
            {
                return entry;
            }
        }
        else if (type == KerberosAuthorizationDataType.KERB_AD_RESTRICTION_ENTRY)
        {
            if (KerberosAuthorizationDataRestrictionEntry.Parse(data,
                out KerberosAuthorizationDataRestrictionEntry entry))
            {
                return entry;
            }
        }
        else if (type == KerberosAuthorizationDataType.AD_ETYPE_NEGOTIATION)
        {
            if (KerberosAuthorizationDataEncryptionNegotiation.Parse(data,
                out KerberosAuthorizationDataEncryptionNegotiation entry))
            {
                return entry;
            }
        }
        else if (type == KerberosAuthorizationDataType.AD_WIN2K_PAC)
        {
            if (KerberosAuthorizationDataPAC.Parse(data,
                out KerberosAuthorizationDataPAC entry))
            {
                return entry;
            }
        }
        else if (type == KerberosAuthorizationDataType.AD_AUTH_DATA_AP_OPTIONS)
        {
            if (KerberosAuthorizationDataApOptions.Parse(data,
                out KerberosAuthorizationDataApOptions entry))
            {
                return entry;
            }
        }
        else if (type == KerberosAuthorizationDataType.AD_AUTH_DATA_TARGET_NAME)
        {
            if (KerberosAuthorizationDataTargetName.Parse(data,
                out KerberosAuthorizationDataTargetName entry))
            {
                return entry;
            }
        }
        else if (type == KerberosAuthorizationDataType.KERB_LOCAL)
        {
            if (KerberosAuthorizationDataKerbLocal.Parse(data,
                out KerberosAuthorizationDataKerbLocal entry))
            {
                return entry;
            }
        }

        return new KerberosAuthorizationDataRaw(type, data);
    }

    internal static IReadOnlyList<KerberosAuthorizationData> ParseSequence(DERValue value)
    {
        return value.ReadSequence(Parse);
    }

    private protected abstract void FormatData(StringBuilder builder);

    private protected abstract byte[] GetData();

    internal void Format(StringBuilder builder)
    {
        builder.AppendLine($"<Authorization Data - {DataType}>");
        FormatData(builder);
        builder.AppendLine();
    }

    void IDERObject.Write(DERBuilder builder)
    {
        using var seq = builder.CreateSequence();
        seq.WriteContextSpecific(0, (int)DataType);
        seq.WriteContextSpecific(1, GetData());
    }

    internal byte[] ToArray()
    {
        DERBuilder builder = new();
        builder.WriteObject(this);
        return builder.ToArray();
    }
}
