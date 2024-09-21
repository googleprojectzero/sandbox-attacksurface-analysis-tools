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
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent a Kerberos ticket.
    /// </summary>
    public class KerberosTicket :IDERObject
    {
        /// <summary>
        /// Version number for the ticket.
        /// </summary>
        public int TicketVersion { get; private set; }
        /// <summary>
        /// Realm.
        /// </summary>
        public string Realm { get; private set; }
        /// <summary>
        /// Server name.
        /// </summary>
        public KerberosPrincipalName ServerName { get; private set; }
        /// <summary>
        /// Encrypted data for the ticket.
        /// </summary>
        public KerberosEncryptedData EncryptedData { get; private set; }
        /// <summary>
        /// Get the principal for the ticket.
        /// </summary>
        public string Principal => ServerName.GetPrincipal(Realm);
        /// <summary>
        /// Indicates that the ticket has been decrypted.
        /// </summary>
        public bool Decrypted => this is KerberosTicketDecrypted;

        internal bool TryDecrypt(KerberosKeySet keyset, KerberosKeyUsage key_usage, out KerberosTicketDecrypted ticket)
        {
            if (this is KerberosTicketDecrypted ticket_dec)
            {
                ticket = ticket_dec;
                return true;
            }

            ticket = null;
            if (!EncryptedData.Decrypt(keyset, Realm, ServerName, key_usage, out byte[] decrypted))
                return false;

            return KerberosTicketDecrypted.Parse(this, decrypted, keyset, out ticket);
        }

        private protected virtual void FormatTicketData(StringBuilder builder)
        {
            builder.Append(EncryptedData.Format());
        }

        /// <summary>
        /// Decrypt the kerberos ticket.
        /// </summary>
        /// <param name="keyset">The Kerberos key set containing the keys.</param>
        /// <param name="key_usage">The key usage for the decryption.</param>
        /// <returns>The decrypted kerberos ticket.</returns>
        public KerberosTicketDecrypted Decrypt(KerberosKeySet keyset, KerberosKeyUsage key_usage = KerberosKeyUsage.AsRepTgsRepTicket)
        {
            if (!TryDecrypt(keyset, key_usage, out KerberosTicketDecrypted ticket))
                throw new ArgumentException("Couldn't decrypt the kerberos ticket.");
            return ticket;
        }

        /// <summary>
        /// Encrypt the ticket.
        /// </summary>
        /// <param name="key">The key to encrypt the ticket.</param>
        /// <param name="key_usage">The Kerberos key usage for the encryption.</param>
        /// <param name="key_version">Optional key version number.</param>
        /// <returns>The encrypted ticket.</returns>
        public KerberosTicket Encrypt(KerberosAuthenticationKey key, KerberosKeyUsage key_usage = KerberosKeyUsage.AsRepTgsRepTicket, int? key_version = null)
        {
            return new KerberosTicket(TicketVersion, Realm, ServerName, EncryptedData.Encrypt(key, key_usage, key_version));
        }

        /// <summary>
        /// Format the ticket to a string.
        /// </summary>
        /// <returns>The ticket as a string.</returns>
        public string Format()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine($"Ticket Version  : {TicketVersion}");
            builder.AppendLine($"Server Name     : {ServerName}");
            builder.AppendLine($"Realm           : {Realm}");
            FormatTicketData(builder);
            return builder.ToString();
        }

        /// <summary>
        /// Convert the ticket to an array.
        /// </summary>
        /// <returns>The ticket as an array.</returns>
        public byte[] ToArray()
        {
            DERBuilder builder = new DERBuilder();
            builder.WriteObject(this);
            return builder.ToArray();
        }

        /// <summary>
        /// Create a new ticket.
        /// </summary>
        /// <param name="realm">The server realm.</param>
        /// <param name="server_name">The server name.</param>
        /// <param name="encrypted_data">The ticket encrypted data.</param>
        /// <returns>The new kerberos ticket.</returns>
        public static KerberosTicket Create(string realm,
            KerberosPrincipalName server_name,
            KerberosEncryptedData encrypted_data)
        {
            if (realm is null)
            {
                throw new ArgumentNullException(nameof(realm));
            }

            if (server_name is null)
            {
                throw new ArgumentNullException(nameof(server_name));
            }

            if (encrypted_data is null)
            {
                throw new ArgumentNullException(nameof(encrypted_data));
            }

            return new KerberosTicket(5, realm, server_name, encrypted_data);
        }

        /// <summary>
        /// Parse a Kerberos ticket from a DER encoded byte array.
        /// </summary>
        /// <param name="data">The DER encoded ticket.</param>
        /// <returns></returns>
        public static KerberosTicket Parse(byte[] data)
        {
            DERValue[] values = DERParser.ParseData(data, 0);
            if (values.Length != 1)
                throw new InvalidDataException("Invalid kerberos ticket structure.");
            return Parse(values[0]);
        }

        internal static bool TryParse(byte[] data, out KerberosTicket ticket)
        {
            ticket = null;
            try
            {
                ticket = Parse(data);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private protected KerberosTicket(
            int ticket_version,
            string realm, 
            KerberosPrincipalName server_name, 
            KerberosEncryptedData encrypted_data)
        {
            TicketVersion = ticket_version;
            Realm = realm ?? string.Empty;
            ServerName = server_name ?? new KerberosPrincipalName();
            EncryptedData = encrypted_data;
        }

        internal KerberosTicket() : this(5, null, null, null)
        {
        }

        internal static KerberosTicket Parse(DERValue value)
        {
            if (!value.CheckApplication(1) || !value.HasChildren())
                throw new InvalidDataException();

            if (!value.Children[0].CheckSequence())
                throw new InvalidDataException();

            KerberosTicket ret = new KerberosTicket();
            foreach (var next in value.Children[0].Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    throw new InvalidDataException();
                switch (next.Tag)
                {
                    case 0:
                        ret.TicketVersion = next.ReadChildInteger();
                        break;
                    case 1:
                        ret.Realm = next.ReadChildGeneralString();
                        break;
                    case 2:
                        if (!next.Children[0].CheckSequence())
                        {
                            throw new InvalidDataException();
                        }
                        ret.ServerName = KerberosPrincipalName.Parse(next.Children[0]);
                        break;
                    case 3:
                        if (!next.HasChildren())
                            throw new InvalidDataException();
                        ret.EncryptedData = KerberosEncryptedData.Parse(next.Children[0], next.Data);
                        break;
                    default:
                        throw new InvalidDataException();
                }
            }
            return ret;
        }

        void IDERObject.Write(DERBuilder builder)
        {
            using (var app = builder.CreateApplication(1))
            {
                using (var seq = app.CreateSequence())
                {
                    seq.WriteContextSpecific(0, TicketVersion);
                    seq.WriteContextSpecific(1, Realm);
                    seq.WriteContextSpecific(2, ServerName);
                    seq.WriteContextSpecific(3, EncryptedData);
                }
            }
        }
    }
}
