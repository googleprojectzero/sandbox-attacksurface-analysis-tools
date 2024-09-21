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
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Encrypted part for AP-REP messages.
    /// </summary>
    public class KerberosAPReplyEncryptedPart : KerberosEncryptedData
    {
        /// <summary>
        /// Client uS.
        /// </summary>
        public int ClientUSec { get; private set; }
        /// <summary>
        /// Client time.
        /// </summary>
        public KerberosTime ClientTime { get; private set; }
        /// <summary>
        /// Subkey.
        /// </summary>
        public KerberosAuthenticationKey SubKey { get; private set; }
        /// <summary>
        /// Sequence number.
        /// </summary>
        public int? SequenceNumber { get; private set; }

        internal override string Format()
        {
            StringBuilder builder = new StringBuilder();
            if (ClientTime != null)
            {
                builder.AppendLine($"Client Time     : {ClientTime.ToDateTime(ClientUSec)}");
            }
            if (SubKey != null)
            {
                builder.AppendLine("<Sub Session Key>");
                builder.AppendLine($"Encryption Type : {SubKey.KeyEncryption}");
                builder.AppendLine($"Encryption Key  : {NtObjectUtils.ToHexString(SubKey.Key)}");
            }
            if (SequenceNumber.HasValue)
            {
                builder.AppendLine($"Sequence Number : 0x{SequenceNumber:X}");
            }
            
            return builder.ToString();
        }

        private KerberosAPReplyEncryptedPart(KerberosEncryptedData orig_data)
            : base(orig_data.EncryptionType, orig_data.KeyVersion, orig_data.CipherText)
        {
        }

        internal static bool Parse(KerberosEncryptedData orig_data, byte[] decrypted, out KerberosEncryptedData ticket)
        {
            ticket = null;
            try
            {
                DERValue[] values = DERParser.ParseData(decrypted, 0);
                if (values.Length != 1)
                    return false;
                DERValue value = values[0];
                if (!value.CheckApplication(27) || !value.HasChildren())
                    return false;
                if (!value.Children[0].CheckSequence())
                    return false;
                var ret = new KerberosAPReplyEncryptedPart(orig_data);
                foreach (var next in value.Children[0].Children)
                {
                    if (next.Type != DERTagType.ContextSpecific)
                        return false;
                    switch (next.Tag)
                    {
                        case 0:
                            ret.ClientTime = next.ReadChildKerberosTime();
                            break;
                        case 1:
                            ret.ClientUSec = next.ReadChildInteger();
                            break;
                        case 2:
                            if (!next.HasChildren())
                                return false;
                            ret.SubKey = KerberosAuthenticationKey.Parse(next.Children[0], string.Empty, new KerberosPrincipalName());
                            break;
                        case 3:
                            ret.SequenceNumber = next.ReadChildInteger();
                            break;
                        default:
                            return false;
                    }
                }
                ticket = ret;
            }
            catch (InvalidDataException)
            {
                return false;
            }
            catch (EndOfStreamException)
            {
                return false;
            }
            return true;
        }
    }
}
