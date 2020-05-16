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
    /// Class to represent a Kerberos ticket.
    /// </summary>
    public class KerberosTicket
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

        internal byte[] TicketData { get; }

        internal bool Decrypt(KerberosKeySet keyset, KeyUsage key_usage, out KerberosTicket ticket)
        {
            if (this is KerberosTicketDecrypted)
            {
                ticket = this;
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

        internal string Format()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine($"Ticket Version  : {TicketVersion}");
            builder.AppendLine($"Server Name     : {ServerName}");
            builder.AppendLine($"Realm           : {Realm}");
            FormatTicketData(builder);
            return builder.ToString();
        }

        private protected KerberosTicket(
            int ticket_version,
            string realm, 
            KerberosPrincipalName server_name, 
            KerberosEncryptedData encrypted_data,
            byte[] ticket_data)
        {
            TicketVersion = ticket_version;
            Realm = realm ?? string.Empty;
            ServerName = server_name ?? new KerberosPrincipalName();
            EncryptedData = encrypted_data;
            TicketData = ticket_data;
        }

        internal KerberosTicket(byte[] ticket_data) 
            : this(5, null, null, null, ticket_data)
        {
        }

        internal static KerberosTicket Parse(DERValue value, byte[] data)
        {
            if (!value.CheckApplication(1) || !value.HasChildren())
                throw new InvalidDataException();

            if (!value.Children[0].CheckSequence())
                throw new InvalidDataException();

            KerberosTicket ret = new KerberosTicket(data);
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
                        ret.EncryptedData = KerberosEncryptedData.Parse(next.Children[0]);
                        break;
                    default:
                        throw new InvalidDataException();
                }
            }
            return ret;
        }
    }
}
