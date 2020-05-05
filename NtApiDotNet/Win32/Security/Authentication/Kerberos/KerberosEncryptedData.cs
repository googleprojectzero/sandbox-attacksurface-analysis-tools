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
using System.IO;
using System.Linq.Expressions;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent Kerberos Encrypted Data.
    /// </summary>
    public class KerberosEncryptedData
    {
        /// <summary>
        /// Encryption type for the CipherText.
        /// </summary>
        public KRB_ENC_TYPE EncryptionType { get; private set; }
        /// <summary>
        /// Key version number.
        /// </summary>
        public int KeyVersion { get; private set; }
        /// <summary>
        /// Cipher Text.
        /// </summary>
        public byte[] CipherText { get; private set; }

        internal KerberosEncryptedData()
        {
            CipherText = new byte[0];
        }

        internal string Format()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine($"Encryption Type : {EncryptionType}");
            builder.AppendLine($"Key Version     : {KeyVersion}");
            HexDumpBuilder hex = new HexDumpBuilder(false, true, false, false, 0);
            hex.Append(CipherText);
            hex.Complete();
            builder.AppendLine($"Cipher Text     :");
            builder.Append(hex);
            return builder.ToString();
        }

        internal static KerberosEncryptedData Parse(DERValue value)
        {
            if (!value.CheckSequence())
                throw new InvalidDataException();

            KerberosEncryptedData ret = new KerberosEncryptedData();
            foreach (var next in value.Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    throw new InvalidDataException();
                switch (next.Tag)
                {
                    case 0:
                        ret.EncryptionType = (KRB_ENC_TYPE)next.ReadChildInteger();
                        break;
                    case 1:
                        ret.KeyVersion = next.ReadChildInteger();
                        break;
                    case 2:
                        ret.CipherText = next.ReadChildOctetString();
                        break;
                    default:
                        throw new InvalidDataException();
                }
            }
            return ret;
        }
    }
}
