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
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// The kerberos encrypted data.
    /// </summary>
    public sealed class KerberosKDCReplyEncryptedPart : KerberosEncryptedData
    {
        /// <summary>
        /// The message type of the encrypted part.
        /// </summary>
        public KerberosMessageType MessageType { get; private set; }

        /// <summary>
        /// The kerberos ticket's session key.
        /// </summary>
        public KerberosAuthenticationKey Key { get; private set; }

        /// <summary>
        /// List of last request times.
        /// </summary>
        public IReadOnlyList<KerberosLastRequest> LastRequest { get; private set; }

        /// <summary>
        /// The nonce value.
        /// </summary>
        public int Nonce { get; private set; }

        /// <summary>
        /// Time for key expiration.
        /// </summary>
        public KerberosTime KeyExpirationTime { get; private set; }

        /// <summary>
        /// The ticket flags.
        /// </summary>
        public KerberosTicketFlags TicketFlags { get; private set; }

        /// <summary>
        /// The authentication time.
        /// </summary>
        public KerberosTime AuthTime { get; private set; }

        /// <summary>
        /// The ticket start time.
        /// </summary>
        public KerberosTime StartTime { get; private set; }

        /// <summary>
        /// The ticket end time.
        /// </summary>
        public KerberosTime EndTime { get; private set; }

        /// <summary>
        /// The ticket renew time.
        /// </summary>
        public KerberosTime RenewTill { get; private set; }

        /// <summary>
        /// The server realm.
        /// </summary>
        public string Realm { get; private set; }

        /// <summary>
        /// The server name.
        /// </summary>
        public KerberosPrincipalName ServerName { get; private set; }

        /// <summary>
        /// The client addresses.
        /// </summary>
        public IReadOnlyList<KerberosHostAddress> ClientAddress { get; private set; }

        /// <summary>
        /// Encypted pre-authentication data.
        /// </summary>
        public IReadOnlyList<KerberosPreAuthenticationData> EncryptedPreAuthentication { get; private set; }

        /// <summary>
        /// Parse a KDC reply part.
        /// </summary>
        /// <param name="data">The KDC reply ASN.1 data.</param>
        /// <returns>The parsed KDC reply part.</returns>
        new public static KerberosKDCReplyEncryptedPart Parse(byte[] data)
        {
            if (!TryParse(data, out KerberosKDCReplyEncryptedPart enc_part))
            {
                throw new InvalidDataException("Invalid KDC reply part.");
            }
            return enc_part;
        }

        private KerberosKDCReplyEncryptedPart(byte[] data) 
            : base(KerberosEncryptionType.NULL, null, data)
        {
        }

        internal static bool TryParse(byte[] data, out KerberosKDCReplyEncryptedPart token)
        {
            token = null;
            try
            {
                return TryParse(data, DERParser.ParseData(data, 0), out token);
            }
            catch (InvalidDataException)
            {
            }

            return false;
        }

        internal static bool TryParse(byte[] data, DERValue[] values, out KerberosKDCReplyEncryptedPart token)
        {
            token = null;
            try
            {
                if (values.Length != 1 || !values[0].HasChildren())
                    return false;

                if (!values[0].CheckMsg(KerberosMessageType.KRB_AS_REP_ENC_PART) && !values[0].CheckMsg(KerberosMessageType.KRB_TGS_REP_ENC_PART))
                {
                    return false;
                }

                var ret = new KerberosKDCReplyEncryptedPart(data);
                ret.MessageType = (KerberosMessageType)values[0].Tag;

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
                            ret.Key = next.ReadChildAuthenticationKey();
                            break;
                        case 1:
                            ret.LastRequest = next.ReadChildSequence(KerberosLastRequest.Parse).ToList().AsReadOnly();
                            break;
                        case 2:
                            ret.Nonce = next.ReadChildInteger();
                            break;
                        case 3:
                            ret.KeyExpirationTime = next.ReadChildKerberosTime();
                            break;
                        case 4:
                            ret.TicketFlags = next.ReadChildBitFlags<KerberosTicketFlags>();
                            break;
                        case 5:
                            ret.AuthTime = next.ReadChildKerberosTime();
                            break;
                        case 6:
                            ret.StartTime = next.ReadChildKerberosTime();
                            break;
                        case 7:
                            ret.EndTime = next.ReadChildKerberosTime();
                            break;
                        case 8:
                            ret.RenewTill = next.ReadChildKerberosTime();
                            break;
                        case 9:
                            ret.Realm = next.ReadChildGeneralString();
                            break;
                        case 10:
                            ret.ServerName = next.ReadChildPrincipalName();
                            break;
                        case 11:
                            ret.ClientAddress = next.ReadChildSequence(KerberosHostAddress.Parse).ToList().AsReadOnly();
                            break;
                        case 12:
                            ret.EncryptedPreAuthentication = next.ReadChildSequence(KerberosPreAuthenticationData.Parse);
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
            }

            return false;
        }
    }
}
