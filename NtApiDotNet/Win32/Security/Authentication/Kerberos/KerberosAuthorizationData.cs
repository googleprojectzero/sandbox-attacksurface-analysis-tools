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

using NtApiDotNet.Utilities.ASN1;
using NtApiDotNet.Utilities.Text;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
#pragma warning disable 1591
    /// <summary>
    /// Type of Authorization Data.
    /// </summary>
    public enum KerberosAuthorizationDataType
    {
        AD_IF_RELEVANT = 1,
        AD_INTENDED_FOR_SERVER = 2,
        AD_INTENDED_FOR_APPLICATION_CLASS = 3,
        AD_KDC_ISSUED = 4,
        AD_AND_OR = 5,
        AD_MANDATORY_TICKET_EXTENSIONS = 6,
        AD_IN_TICKET_EXTENSIONS = 7,
        AD_MANDATORY_FOR_KDC = 8,
        AD_INITIAL_VERIFIED_CAS = 9,
        OSF_DCE = 64,
        SESAME = 65,
        AD_OSF_DCE_PKI_CERTID = 66,
        AD_AUTHENTICATION_STRENGTH = 70,
        AD_FX_FAST_ARMOR = 71,
        AD_FX_FAST_USED = 72,
        AD_LOGIN_ALIAS = 80,
        AD_CAMMAC = 96,
        AD_AUTHENTICATION_INDICATOR = 97,
        AD_WIN2K_PAC = 128,
        AD_ETYPE_NEGOTIATION = 129,
        KERB_AD_RESTRICTION_ENTRY = 141,
        KERB_LOCAL = 142,
        AD_AUTH_DATA_AP_OPTIONS = 143,
        AD_PKU2U_CLIENT_NAME = 143,
        MS_RESERVED_144 = 144,
        MS_RESERVED_145 = 145,
        AD_SIGNTICKET = 512,
        AD_DIAMETER = 513,
        AD_ON_BEHALF_OF = 580,
        AD_BEARER_TOKEN_JWT = 581,
        AD_BEARER_TOKEN_SAML = 582,
        AD_BEARER_TOKEN_OIDC = 583,
        AD_CERT_REQ_AUTHORIZED = 584,
    }
#pragma warning restore 1591

    /// <summary>
    /// Class representing Kerberos authentication data.
    /// </summary>
    public class KerberosAuthorizationData
    {
        /// <summary>
        /// Type of authentication data.
        /// </summary>
        public KerberosAuthorizationDataType DataType { get; }
        /// <summary>
        /// Data bytes.
        /// </summary>
        public byte[] Data { get; }

        private protected KerberosAuthorizationData(KerberosAuthorizationDataType type, byte[] data)
        {
            DataType = type;
            Data = data;
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
                DERValue[] values = DERParser.ParseData(data, 0);
                if (values.Length != 1 || !values[0].CheckSequence() || !values[0].HasChildren())
                    throw new InvalidDataException();

                return Parse(values[0].Children[0]);
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

            return new KerberosAuthorizationData(type, data);
        }

        internal static IReadOnlyList<KerberosAuthorizationData> ParseSequence(DERValue value)
        {
            if (!value.CheckSequence())
                throw new InvalidDataException();
            var ret = new List<KerberosAuthorizationData>();
            foreach (var next in value.Children)
            {
                ret.Add(Parse(next));
            }
            return ret.AsReadOnly();
        }

        private protected virtual void FormatData(StringBuilder builder)
        {
            HexDumpBuilder hex = new HexDumpBuilder(false, false, true, false, 0);
            hex.Append(Data);
            hex.Complete();
            builder.AppendLine(hex.ToString());
        }

        internal void Format(StringBuilder builder)
        {
            builder.AppendLine($"<Authorization Data - {DataType}>");
            FormatData(builder);
        }
    }
}
