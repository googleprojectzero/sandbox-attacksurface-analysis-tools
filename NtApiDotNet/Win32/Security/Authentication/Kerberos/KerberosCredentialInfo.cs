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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Represents a KrbCredInfo structure.
    /// </summary>
    public sealed class KerberosCredentialInfo : IDERObject
    {
        /// <summary>
        /// The kerberos session key.
        /// </summary>
        public KerberosAuthenticationKey Key { get; private set; }
        /// <summary>
        /// Ticket flags.
        /// </summary>
        public KerberosTicketFlags? TicketFlags { get; private set; }
        /// <summary>
        /// Client Realm.
        /// </summary>
        public string ClientRealm { get; private set; }
        /// <summary>
        /// Client name.
        /// </summary>
        public KerberosPrincipalName ClientName { get; private set; }
        /// <summary>
        /// Authentication time.
        /// </summary>
        public KerberosTime AuthTime { get; private set; }
        /// <summary>
        /// Start time.
        /// </summary>
        public KerberosTime StartTime { get; private set; }
        /// <summary>
        /// End time.
        /// </summary>
        public KerberosTime EndTime { get; private set; }
        /// <summary>
        /// Renew till time.
        /// </summary>
        public KerberosTime RenewTill { get; private set; }
        /// <summary>
        /// Server Realm.
        /// </summary>
        public string Realm { get; private set; }
        /// <summary>
        /// Server name.
        /// </summary>
        public KerberosPrincipalName ServerName { get; private set; }
        /// <summary>
        /// List of host addresses for ticket.
        /// </summary>
        public IReadOnlyList<KerberosHostAddress> HostAddresses { get; private set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="key">The kerberos session key.</param>
        /// <param name="client_realm">Client realm.</param>
        /// <param name="client_name">Client name.</param>
        /// <param name="ticket_flags">Ticket flags.</param>
        /// <param name="auth_time">Authentication time.</param>
        /// <param name="start_time">Start time.</param>
        /// <param name="end_time">End time.</param>
        /// <param name="renew_till">Renew till time.</param>
        /// <param name="realm">Server Realm.</param>
        /// <param name="server_name">Server name.</param>
        /// <param name="host_addresses">List of host addresses for ticket.</param>
        public KerberosCredentialInfo(KerberosAuthenticationKey key, string client_realm = null,
            KerberosPrincipalName client_name = null, KerberosTicketFlags? ticket_flags = null,
            KerberosTime auth_time = null, KerberosTime start_time = null, KerberosTime end_time = null,
            KerberosTime renew_till = null, string realm = null, KerberosPrincipalName server_name = null,
            IEnumerable<KerberosHostAddress> host_addresses = null)
        {
            Key = key;
            ClientRealm = client_realm;
            ClientName = client_name;
            TicketFlags = ticket_flags;
            AuthTime = auth_time;
            StartTime = start_time;
            EndTime = end_time;
            RenewTill = renew_till;
            Realm = realm;
            ServerName = server_name;
            HostAddresses = host_addresses?.ToList().AsReadOnly();
        }

        private KerberosCredentialInfo()
        {
        }

        internal string Format()
        {
            StringBuilder builder = new StringBuilder();

            builder.AppendLine($"Realm           : {Realm}");
            builder.AppendLine($"Server Name     : {ServerName}");
            builder.AppendLine($"Client Name     : {ClientName}");
            builder.AppendLine($"Client Realm    : {ClientRealm}");

            if (AuthTime != null)
            {
                builder.AppendLine($"Auth Time       : {AuthTime.ToDateTime()}");
            }
            if (StartTime != null)
            {
                builder.AppendLine($"Start Time     : {StartTime.ToDateTime()}");
            }
            if (EndTime != null)
            {
                builder.AppendLine($"End Time       : {EndTime.ToDateTime()}");
            }
            if (RenewTill != null)
            {
                builder.AppendLine($"Renew Time     : {EndTime.ToDateTime()}");
            }
            builder.AppendLine($"Ticket Flags    : {TicketFlags}");

            builder.AppendLine("<Session Key>");
            builder.AppendLine($"Encryption Type : {Key.KeyEncryption}");
            builder.AppendLine($"Encryption Key  : {NtObjectUtils.ToHexString(Key.Key)}");

            if (HostAddresses?.Count > 0)
            {
                builder.AppendLine("<Host Addresses>");
                foreach (var addr in HostAddresses)
                {
                    builder.AppendLine(addr.ToString());
                }
            }

            return builder.ToString();
        }

        internal static KerberosCredentialInfo Parse(DERValue value, KerberosKeySet keyset, KerberosTicket orig_ticket)
        {
            if (!value.HasChildren() || !value.CheckSequence())
                throw new InvalidDataException();
            var ret = new KerberosCredentialInfo();

            foreach (var next in value.Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    throw new InvalidDataException();
                switch (next.Tag)
                {
                    case 0:
                        if (!next.HasChildren())
                            throw new InvalidDataException();
                        ret.Key = KerberosAuthenticationKey.Parse(next.Children[0], orig_ticket.Realm, orig_ticket.ServerName);
                        keyset.Add(ret.Key);
                        break;
                    case 1:
                        ret.ClientRealm = next.ReadChildGeneralString();
                        break;
                    case 2:
                        if (!next.Children[0].CheckSequence())
                            throw new InvalidDataException();
                        ret.ClientName = KerberosPrincipalName.Parse(next.Children[0]);
                        break;
                    case 3:
                        ret.TicketFlags = next.ReadChildBitFlags<KerberosTicketFlags>();
                        break;
                    case 4:
                        ret.AuthTime = next.ReadChildKerberosTime();
                        break;
                    case 5:
                        ret.StartTime = next.ReadChildKerberosTime();
                        break;
                    case 6:
                        ret.EndTime = next.ReadChildKerberosTime();
                        break;
                    case 7:
                        ret.RenewTill = next.ReadChildKerberosTime();
                        break;
                    case 8:
                        ret.Realm = next.ReadChildGeneralString();
                        break;
                    case 9:
                        if (!next.Children[0].CheckSequence())
                            throw new InvalidDataException();
                        ret.ServerName = KerberosPrincipalName.Parse(next.Children[0]);
                        break;
                    case 10:
                        if (!next.HasChildren())
                            throw new InvalidDataException();
                        ret.HostAddresses = KerberosHostAddress.ParseSequence(next.Children[0]);
                        break;
                    default:
                        throw new InvalidDataException();
                }
            }

            return ret;
        }

        void IDERObject.Write(DERBuilder builder)
        {
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, Key);
                seq.WriteContextSpecific(1, ClientRealm);
                seq.WriteContextSpecific(2, ClientName);
                if (TicketFlags.HasValue)
                {
                    seq.WriteContextSpecific(3, b => b.WriteBitString(TicketFlags.Value));
                }
                seq.WriteContextSpecific(4, AuthTime);
                seq.WriteContextSpecific(5, StartTime);
                seq.WriteContextSpecific(6, EndTime);
                seq.WriteContextSpecific(7, RenewTill);
                seq.WriteContextSpecific(8, Realm);
                seq.WriteContextSpecific(9, ServerName);
                seq.WriteContextSpecific(10, HostAddresses);
            }
        }
    }
}
