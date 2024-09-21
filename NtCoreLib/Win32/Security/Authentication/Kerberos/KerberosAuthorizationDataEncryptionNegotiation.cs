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
using NtApiDotNet.Utilities.ASN1.Builder;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent AD_ETYPE_NEGOTIATION type.
    /// </summary>
    public sealed class KerberosAuthorizationDataEncryptionNegotiation : KerberosAuthorizationData
    {
        /// <summary>
        /// List of supported encryption types.
        /// </summary>
        public IReadOnlyList<KerberosEncryptionType> EncryptionList { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="enc_list">The list of encryption types.</param>
        public KerberosAuthorizationDataEncryptionNegotiation(IEnumerable<KerberosEncryptionType> enc_list) 
            : base(KerberosAuthorizationDataType.AD_ETYPE_NEGOTIATION)
        {
            EncryptionList = enc_list.ToList().AsReadOnly();
        }

        private protected override void FormatData(StringBuilder builder)
        {
            builder.AppendLine(string.Join(", ", EncryptionList));
        }

        internal static bool Parse(byte[] data, out KerberosAuthorizationDataEncryptionNegotiation entry)
        {
            entry = null;
            DERValue[] values = DERParser.ParseData(data, 0);
            if (!values.CheckValueSequence())
                return false;
            List<KerberosEncryptionType> enc_types = new List<KerberosEncryptionType>();
            try
            {
                foreach (var next in values[0].Children)
                {
                    if (!next.CheckPrimitive(UniversalTag.INTEGER))
                        return false;
                    enc_types.Add((KerberosEncryptionType)next.ReadInteger());
                }
            }
            catch (InvalidDataException)
            {
                return false;
            }

            entry = new KerberosAuthorizationDataEncryptionNegotiation(enc_types.AsReadOnly());
            return true;
        }

        private protected override byte[] GetData()
        {
            DERBuilder builder = new DERBuilder();
            using (var seq = builder.CreateSequence())
            {
                foreach (var value in EncryptionList)
                {
                    seq.WriteInt32((int)value);
                }
            }
            return builder.ToArray();
        }
    }
}
