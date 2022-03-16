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
using NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder;
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
        public KerberosTime ClientTime { get; private set; }
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
        /// Convert the authenticator a builder based on the current values.
        /// </summary>
        /// <returns>The builder object.</returns>
        public KerberosAuthenticatorBuilder ToBuilder()
        {
            return new KerberosAuthenticatorBuilder()
            {
                ClientName = ClientName,
                ClientRealm = ClientRealm,
                AuthorizationData = AuthorizationData?.ToList(),
                Checksum = Checksum,
                ClientTime = ClientTime,
                ClientUSec = ClientUSec,
                SequenceNumber = SequenceNumber,
                SubKey = SubKey
            };
        }

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
            KerberosTime client_time, int client_usec = 0, KerberosChecksum checksum = null, KerberosAuthenticationKey subkey = null, 
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

            if (client_time is null)
            {
                throw new ArgumentNullException(nameof(client_time));
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
                    seq.WriteContextSpecific(4, b => b.WriteInt32(client_usec));
                    seq.WriteContextSpecific(5, client_time);
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

            return new KerberosAuthenticator(builder.ToArray())
            {
                ClientName = client_name,
                ClientRealm = client_realm,
                ClientTime = client_time,
                ClientUSec = client_usec,
                Checksum = checksum,
                SubKey = subkey,
                SequenceNumber = sequence_number,
                AuthorizationData = authorization_data?.ToList().AsReadOnly()
            };
        }

        internal override string Format()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine($"Client Name     : {ClientName}");
            builder.AppendLine($"Client Realm    : {ClientRealm}");
            if (ClientTime != null)
            {
                builder.AppendLine($"Client Time     : {ClientTime.ToDateTime(ClientUSec)}");
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

        /// <summary>
        /// Try and parse an authenticator from DER encoded data.
        /// </summary>
        /// <param name="data">The DER encoded data.</param>
        /// <param name="authenticator">The parsed authenticator.</param>
        /// <returns>True the parse was successful.</returns>
        public static bool TryParse(byte[] data, out KerberosAuthenticator authenticator)
        {
            return TryParse(null, data, null, out authenticator);
        }

        /// <summary>
        /// Parse an authenticator from DER encoded data.
        /// </summary>
        /// <param name="data">The DER encoded data.</param>
        public static KerberosAuthenticator Parse(byte[] data)
        {
            if (TryParse(data, out KerberosAuthenticator authenticator))
                return authenticator;
            throw new InvalidDataException("Failed to parse authenticator.");
        }

        private KerberosAuthenticator(byte[] decrypted) 
            : base(KerberosEncryptionType.NULL, null, decrypted)
        {
            AuthenticatorVersion = 5;
        }

        internal static bool TryParse(KerberosTicket ticket, byte[] decrypted, KerberosKeySet keyset, out KerberosAuthenticator authenticator)
        {
            authenticator = null;
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
                var ret = new KerberosAuthenticator(decrypted);
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
                            ret.ClientTime = next.ReadChildKerberosTime();
                            break;
                        case 6:
                            if (!next.HasChildren())
                                return false;
                            ret.SubKey = KerberosAuthenticationKey.Parse(next.Children[0], ticket?.Realm ?? "Unknown", 
                                ticket.ServerName ?? new KerberosPrincipalName());
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
                    KerberosKeySet tmp_keyset = new KerberosKeySet(keyset?.AsEnumerable() ?? new KerberosAuthenticationKey[0]);
                    if (ret.SubKey != null)
                    {
                        tmp_keyset.Add(ret.SubKey);
                    }

                    gssapi.Decrypt(tmp_keyset);
                }

                authenticator = ret;
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
