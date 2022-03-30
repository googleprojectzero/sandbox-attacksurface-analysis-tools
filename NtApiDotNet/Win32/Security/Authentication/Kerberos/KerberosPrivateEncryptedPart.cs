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
using NtApiDotNet.Utilities.Text;
using System;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent the EncKrbPrivPart structure.
    /// </summary>
    public sealed class KerberosPrivateEncryptedPart : KerberosEncryptedData
    {
        /// <summary>
        /// The user data.
        /// </summary>
        public byte[] UserData { get; private set; }

        /// <summary>
        /// The sequence number.
        /// </summary>
        public int? SequenceNumber { get; private set; }

        /// <summary>
        /// The private timestamp.
        /// </summary>
        public KerberosTime Timestamp { get; private set; }

        /// <summary>
        /// The private usecs.
        /// </summary>
        public int? USec { get; private set; }

        /// <summary>
        /// The private's sender address.
        /// </summary>
        public KerberosHostAddress SenderAddress { get; private set; }

        /// <summary>
        /// The private's recipient address.
        /// </summary>
        public KerberosHostAddress RecipientAddress { get; private set; }

        /// <summary>
        /// Create a new private encrypted part.
        /// </summary>
        /// <param name="user_data">The user data.</param>
        /// <param name="timestamp">The credentials timestamp.</param>
        /// <param name="usec">The credentials usecs.</param>
        /// <param name="sender_address">The credentials sender address.</param>
        /// <param name="recipient_address">The credentials recipient address.</param>
        /// <param name="sequence_number">The sequence number.</param>
        /// <returns>The credentials encrypted part.</returns>
        public static KerberosEncryptedData Create(byte[] user_data, KerberosHostAddress sender_address, int? sequence_number = null, KerberosTime timestamp = null,
            int? usec = null, KerberosHostAddress recipient_address = null)
        {
            if (user_data is null)
            {
                throw new ArgumentNullException(nameof(user_data));
            }

            if (sender_address is null)
            {
                throw new ArgumentNullException(nameof(sender_address));
            }

            DERBuilder builder = new DERBuilder();
            using (var app = builder.CreateApplication((int)KerberosMessageType.KRB_PRIV_ENC_PART))
            {
                using (var seq = app.CreateSequence())
                {
                    seq.WriteContextSpecific(0, user_data);
                    seq.WriteContextSpecific(1, timestamp);
                    seq.WriteContextSpecific(2, usec);
                    seq.WriteContextSpecific(3, sequence_number);
                    seq.WriteContextSpecific(4, sender_address);
                    seq.WriteContextSpecific(5, recipient_address);
                }
            }
            return Create(KerberosEncryptionType.NULL, builder.ToArray());
        }

        private KerberosPrivateEncryptedPart(byte[] data) :
            base(KerberosEncryptionType.NULL, null, data)
        {
        }

        private KerberosPrivateEncryptedPart(KerberosEncryptedData data) :
            base(data.EncryptionType, data.KeyVersion, data.CipherText)
        {
        }

        internal override string Format()
        {
            StringBuilder builder = new StringBuilder();
            if (Timestamp != null)
            {
                builder.AppendLine($"Timestamp       : {Timestamp.ToDateTime(USec)}");
            }
            if (SequenceNumber.HasValue)
            {
                builder.AppendLine($"Sequence Number : {SequenceNumber.Value}");
            }
            builder.AppendLine($"Sender Address  : {SenderAddress}");
            if (RecipientAddress != null)
            {
                builder.AppendLine($"Recipient Address: {RecipientAddress}");
            }
            HexDumpBuilder hex_dump = new HexDumpBuilder(true, true, true, true, 0);
            hex_dump.Append(UserData);
            hex_dump.Complete();
            builder.AppendLine("User Data       :");
            builder.Append(hex_dump);
            return builder.ToString();
        }

        internal static bool TryParse(KerberosEncryptedData orig_data, byte[] decrypted, out KerberosPrivateEncryptedPart token)
        {
            token = null;
            try
            {
                DERValue[] values = DERParser.ParseData(decrypted, 0);
                var ret = new KerberosPrivateEncryptedPart(orig_data);
                if (values.Length != 1 || !values[0].CheckMsg(KerberosMessageType.KRB_PRIV_ENC_PART) || !values[0].HasChildren())
                    return false;

                values = values[0].Children;
                if (values.Length != 1 || !values[0].CheckSequence() || !values[0].HasChildren())
                    return false;

                foreach (var next in values[0].Children)
                {
                    if (next.Type != DERTagType.ContextSpecific)
                        return false;
                    switch (next.Tag)
                    {
                        case 0:
                            ret.UserData = next.ReadChildOctetString();
                            break;
                        case 1:
                            ret.Timestamp = next.ReadChildKerberosTime();
                            break;
                        case 2:
                            ret.USec = next.ReadChildInteger();
                            break;
                        case 3:
                            ret.SequenceNumber = next.ReadChildInteger();
                            break;
                        case 4:
                            ret.SenderAddress = KerberosHostAddress.ParseChild(next);
                            break;
                        case 5:
                            ret.RecipientAddress = KerberosHostAddress.ParseChild(next);
                            break;
                        default:
                            return false;
                    }
                }
                token = ret;
                return true;
            }
            catch (InvalidDataException)
            {
                return false;
            }
        }
    }
}
