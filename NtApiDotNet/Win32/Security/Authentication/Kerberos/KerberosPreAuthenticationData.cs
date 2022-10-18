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

using NtApiDotNet.Utilities.ASN1;
using NtApiDotNet.Utilities.ASN1.Builder;
using NtApiDotNet.Win32.Security.Authentication.Kerberos.PkInit;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent a Kerberos PA-DATA structure.
    /// </summary>
    public abstract class KerberosPreAuthenticationData : IDERObject
    {
        /// <summary>
        /// The type of pre-authentication data.
        /// </summary>
        public KerberosPreAuthenticationType Type { get; }

        private protected KerberosPreAuthenticationData(KerberosPreAuthenticationType type)
        {
            Type = type;
        }

        private protected abstract byte[] GetData();

        private protected virtual void Format(StringBuilder builder)
        {
        }

        /// <summary>
        /// Format the PA-DATA to a string.
        /// </summary>
        /// <returns>The PA-DATA as a string.</returns>
        public string Format()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine($"<Kerberos PA-DATA {Type}>");
            Format(builder);
            return builder.ToString();
        }

        internal static List<KerberosPreAuthenticationData> ParseErrorData(byte[] error_data)
        {
            List<KerberosPreAuthenticationData> ret = new List<KerberosPreAuthenticationData>();

            try
            {
                DERValue[] values = DERParser.ParseData(error_data, 0);
                if (!values.CheckValueSequence())
                    return ret;
                foreach (var next in values[0].Children)
                {
                    ret.Add(Parse(next));
                }
            }
            catch
            {
            }
            return ret;
        }

        internal static KerberosPreAuthenticationData Parse(DERValue value)
        {
            if (!value.CheckSequence())
            {
                throw new InvalidDataException();
            }
            KerberosPreAuthenticationType type = KerberosPreAuthenticationType.None;
            byte[] data = null;
            foreach (var next in value.Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    throw new InvalidDataException();
                switch (next.Tag)
                {
                    case 1:
                        type = (KerberosPreAuthenticationType)next.ReadChildInteger();
                        break;
                    case 2:
                        data = next.ReadChildOctetString();
                        break;
                    default:
                        throw new InvalidDataException();
                }
            }

            if (data == null || data.Length == 0)
            {
                return new KerberosPreAuthenticationDataUnknown(type, data);
            }

            switch (type)
            {
                case KerberosPreAuthenticationType.PA_TGS_REQ:
                    return KerberosPreAuthenticationDataTGSRequest.Parse(data);
                case KerberosPreAuthenticationType.PA_PAC_OPTIONS:
                    return KerberosPreAuthenticationPACOptions.Parse(data);
                case KerberosPreAuthenticationType.PA_ENC_TIMESTAMP:
                    return KerberosPreAuthenticationDataEncTimestamp.Parse(data);
                case KerberosPreAuthenticationType.PA_ETYPE_INFO:
                    return KerberosPreAuthenticationDataEncryptionTypeInfo.Parse(data);
                case KerberosPreAuthenticationType.PA_ETYPE_INFO2:
                    return KerberosPreAuthenticationDataEncryptionTypeInfo2.Parse(data);
                case KerberosPreAuthenticationType.PA_PK_AS_REP:
                    return KerberosPreAuthenticationDataPkAsRep.Parse(data);
                case KerberosPreAuthenticationType.PA_AS_FRESHNESS:
                    return new KerberosPreAuthenticationDataAsFreshness(data);
                case KerberosPreAuthenticationType.PA_PK_AS_REQ:
                    return KerberosPreAuthenticationDataPkAsReq.Parse(data);
                default:
                    return new KerberosPreAuthenticationDataUnknown(type, data);
            }
        }

        void IDERObject.Write(DERBuilder builder)
        {
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(1, (int)Type);
                seq.WriteContextSpecific(2, GetData());
            }
        }
    }
}
