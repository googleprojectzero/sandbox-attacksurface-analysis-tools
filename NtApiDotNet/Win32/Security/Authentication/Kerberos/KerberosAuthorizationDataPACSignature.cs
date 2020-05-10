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

using System;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent a PAC signature.
    /// </summary>
    public class KerberosAuthorizationDataPACSignature : KerberosAuthorizationDataPACEntry
    {
        /// <summary>
        /// Signature type.
        /// </summary>
        public KerberosChecksumType SignatureType { get; }
        /// <summary>
        /// Signature.
        /// </summary>
        public byte[] Signature { get; }
        /// <summary>
        /// Read-only Domain Controller Identifier.
        /// </summary>
        public int? RODCIdentifier { get; }

        private KerberosAuthorizationDataPACSignature(KerberosAuthorizationDataPACEntryType type, byte[] data, KerberosChecksumType sig_type,
            byte[] signature, int? rodc_id)
            : base(type, data)
        {
            SignatureType = sig_type;
            Signature = signature;
            RODCIdentifier = rodc_id;
        }

        private protected override void FormatData(StringBuilder builder)
        {
            builder.AppendLine($"Signature Type   : {SignatureType}");
            builder.AppendLine($"Signature        : {NtObjectUtils.ToHexString(Signature)}");
            if (RODCIdentifier.HasValue)
            {
                builder.AppendLine($"RODC Identifier  : {RODCIdentifier}");
            }
        }

        internal static bool Parse(KerberosAuthorizationDataPACEntryType type, byte[] data, out KerberosAuthorizationDataPACEntry entry)
        {
            entry = null;

            if (data.Length < 4)
                return false;

            int signature_length = 0;
            KerberosChecksumType signature_type = (KerberosChecksumType)BitConverter.ToInt32(data, 0);
            switch (signature_type)
            {
                case KerberosChecksumType.HMAC_MD5:
                    signature_length = 16;
                    break;
                case KerberosChecksumType.HMAC_SHA1_96_AES_128:
                case KerberosChecksumType.HMAC_SHA1_96_AES_256:
                    signature_length = 12;
                    break;
                default:
                    signature_length = data.Length - 4;
                    break;
            }

            byte[] signature = new byte[signature_length];
            Buffer.BlockCopy(data, 4, signature, 0, signature_length);
            int? rodc_id = null;
            int total_size = 4 + signature_length;
            if (data.Length - total_size >= 2)
            {
                rodc_id = BitConverter.ToUInt16(data, total_size);
            }
                
            entry = new KerberosAuthorizationDataPACSignature(type, data, signature_type, signature, rodc_id);
            return true;
        }
    }
}
