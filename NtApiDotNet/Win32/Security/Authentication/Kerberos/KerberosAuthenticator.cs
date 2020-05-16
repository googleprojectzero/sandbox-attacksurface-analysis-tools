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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent a 
    /// </summary>
    public class KerberosAuthenticator : KerberosEncryptedData
    {
        /// <summary>
        /// Authenticator version.
        /// </summary>
        public int AuthenticatorVersion { get; }
        /// <summary>
        /// Client realm.
        /// </summary>
        public string ClientRealm { get; private set; }
        /// <summary>
        /// Client name.
        /// </summary>
        public KerberosPrincipalName ClientName { get; private set; }
        /// <summary>
        /// Checksum value.
        /// </summary>
        public KerberosChecksum Checksum { get; private set; }
        /// <summary>
        /// Client uS.
        /// </summary>
        public int ClientUSec { get; private set; }
        /// <summary>
        /// Client time.
        /// </summary>
        public string ClientTime { get; private set; }
        /// <summary>
        /// Subkey.
        /// </summary>
        public KerberosAuthenticationKey SubKey { get; private set; }
        /// <summary>
        /// Sequence number.
        /// </summary>
        public int? SequenceNumber { get; private set; }
        /// <summary>
        /// Authorization data.
        /// </summary>
        public IReadOnlyList<KerberosAuthorizationData> AuthorizationData { get; private set; }

        internal override string Format()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine($"Client Name     : {ClientName}");
            builder.AppendLine($"Client Realm    : {ClientRealm}");
            if (!string.IsNullOrEmpty(ClientTime))
            {
                builder.AppendLine($"Client Time     : {KerberosUtils.ParseKerberosTime(ClientTime, ClientUSec)}");
            }
            if (Checksum != null)
            {
                Checksum.Format(builder);
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

            if (AuthorizationData.Count > 0)
            {
                foreach (var ad in AuthorizationData)
                {
                    ad.Format(builder);
                }
                builder.AppendLine();
            }
            return builder.ToString();
        }

        private KerberosAuthenticator(KerberosEncryptedData orig_data) 
            : base(orig_data.EncryptionType, orig_data.KeyVersion, orig_data.CipherText)
        {
            AuthenticatorVersion = 5;
        }

        internal static bool Parse(KerberosTicket orig_ticket, KerberosEncryptedData orig_data, byte[] decrypted, KerberosKeySet keyset, out KerberosEncryptedData ticket)
        {
            ticket = null;
            try
            {
                DERValue[] values = DERParser.ParseData(decrypted, 0);
                if (values.Length != 1)
                    return false;
                DERValue value = values[0];
                if (!value.CheckApplication(2) || !value.HasChildren())
                    return false;
                if (!value.Children[0].CheckSequence())
                    return false;
                var ret = new KerberosAuthenticator(orig_data);
                foreach (var next in value.Children[0].Children)
                {
                    if (next.Type != DERTagType.ContextSpecific)
                        return false;
                    switch (next.Tag)
                    {
                        case 0:
                            if (next.ReadChildInteger() != 5)
                                return false;
                            break;
                        case 1:
                            ret.ClientRealm = next.ReadChildGeneralString();
                            break;
                        case 2:
                            if (!next.Children[0].CheckSequence())
                                return false;
                            ret.ClientName = KerberosPrincipalName.Parse(next.Children[0]);
                            break;
                        case 3:
                            if (!next.Children[0].CheckSequence())
                                return false;
                            ret.Checksum = KerberosChecksum.Parse(next.Children[0]);
                            break;
                        case 4:
                            ret.ClientUSec = next.ReadChildInteger();
                            break;
                        case 5:
                            ret.ClientTime = next.ReadChildGeneralizedTime();
                            break;
                        case 6:
                            if (!next.HasChildren())
                                return false;
                            ret.SubKey = KerberosAuthenticationKey.Parse(next.Children[0], orig_ticket.Realm, orig_ticket.ServerName);
                            break;
                        case 7:
                            ret.SequenceNumber = next.ReadChildInteger();
                            break;
                        case 8:
                            if (!next.HasChildren())
                                return false;
                            ret.AuthorizationData = KerberosAuthorizationData.ParseSequence(next.Children[0]);
                            break;
                        default:
                            return false;
                    }
                }

                if (ret.Checksum is KerberosChecksumGSSApi gssapi && gssapi.Credentials != null)
                {
                    KerberosKeySet tmp_keyset = new KerberosKeySet(keyset.AsEnumerable() ?? new KerberosAuthenticationKey[0]);
                    if (ret.SubKey != null)
                    {
                        tmp_keyset.Add(ret.SubKey);
                    }

                    gssapi.Decrypt(tmp_keyset);
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
