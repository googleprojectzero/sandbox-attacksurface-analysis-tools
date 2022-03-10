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
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent an unencrypted kerberos authenticator.
    /// </summary>
    public class KerberosAuthenticator : KerberosEncryptedData
    {
        /*
            Authenticator   ::= [APPLICATION 2] SEQUENCE  {
            authenticator-vno       [0] INTEGER (5),
            crealm                  [1] Realm,
            cname                   [2] PrincipalName,
            cksum                   [3] Checksum OPTIONAL,
            cusec                   [4] Microseconds,
            ctime                   [5] KerberosTime,
            subkey                  [6] EncryptionKey OPTIONAL,
            seq-number              [7] UInt32 OPTIONAL,
            authorization-data      [8] AuthorizationData OPTIONAL
        }
        */

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

        /// <summary>
        /// Create a new authenticator.
        /// </summary>
        /// <param name="client_realm">The client realm name.</param>
        /// <param name="client_name">The client's principal name.</param>
        /// <param name="client_usec">Client time usecs.</param>
        /// <param name="client_time">Client time.</param>
        /// <param name="checksum">Optional checksum.</param>
        /// <param name="subkey">Optional subkey.</param>
        /// <param name="sequence_number">Optional sequence number.</param>
        /// <param name="authorization_data">Optional authorization data.</param>
        /// <returns>The new authenticator.</returns>
        public static KerberosAuthenticator Create(string client_realm, KerberosPrincipalName client_name, 
            DateTime client_time, int? client_usec = null, KerberosChecksum checksum = null, KerberosAuthenticationKey subkey = null, 
            int? sequence_number = null, IEnumerable<KerberosAuthorizationData> authorization_data = null)
        {
            if (client_realm is null)
            {
                throw new ArgumentNullException(nameof(client_realm));
            }

            if (client_name is null)
            {
                throw new ArgumentNullException(nameof(client_name));
            }

            DERBuilder builder = new DERBuilder();
            using (var app = builder.CreateApplication(2))
            {
                using (var seq = app.CreateSequence())
                {
                    seq.WriteContextSpecific(0, b => b.WriteInt32(5));
                    seq.WriteContextSpecific(1, b => b.WriteGeneralString(client_realm));
                    seq.WriteContextSpecific(2, client_name);
                    if (checksum != null)
                    {
                        seq.WriteContextSpecific(3, checksum);
                    }
                    seq.WriteContextSpecific(4, b => b.WriteGeneralizedTime(client_time));
                    seq.WriteContextSpecific(5, b => b.WriteInt32(client_usec ?? 0));
                    if (subkey != null)
                    {
                        seq.WriteContextSpecific(6, subkey);
                    }
                    if (sequence_number.HasValue)
                    {
                        seq.WriteContextSpecific(7, b => b.WriteInt32(sequence_number.Value));
                    }
                    if (authorization_data != null)
                    {
                        seq.WriteContextSpecific(8, b => b.WriteSequence(authorization_data));
                    }
                }
            }

            return new KerberosAuthenticator(Create(KerberosEncryptionType.NULL, builder.ToArray()))
            {
                ClientName = client_name,
                ClientRealm = client_realm,
                ClientTime = DERUtils.ConvertGeneralizedTime(client_time),
                ClientUSec = client_usec ?? 0,
                Checksum = checksum,
                SubKey = subkey,
                SequenceNumber = sequence_number ?? throw new ArgumentNullException(nameof(sequence_number)),
                AuthorizationData = authorization_data.ToList().AsReadOnly()
            };
        }

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
            : base(orig_data.EncryptionType, orig_data.KeyVersion, orig_data.CipherText, orig_data.Data)
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
