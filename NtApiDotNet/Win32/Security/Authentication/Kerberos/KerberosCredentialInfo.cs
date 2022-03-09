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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Represents a KrbCredInfo structure.
    /// </summary>
    public sealed class KerberosCredentialInfo
    {
        /// <summary>
        /// The kerberos session key.
        /// </summary>
        public KerberosAuthenticationKey Key { get; private set; }

        /// <summary>
        /// Ticket flags.
        /// </summary>
        public KerberosTicketFlags Flags { get; private set; }
        /// <summary>
        /// Client Realm.
        /// </summary>
        public string ClientRealm { get; private set; }
        /// <summary>
        /// Client name.
        /// </summary>
        public KerberosPrincipalName ClientName { get; private set; }
        /// <summary>
        /// Authentication time,
        /// </summary>
        public string AuthTime { get; private set; }
        /// <summary>
        /// Start time.
        /// </summary>
        public string StartTime { get; private set; }
        /// <summary>
        /// End time.
        /// </summary>
        public string EndTime { get; private set; }
        /// <summary>
        /// Renew till time.
        /// </summary>
        public string RenewTill { get; private set; }
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
                        ret.Flags = next.ReadChildBitFlags<KerberosTicketFlags>();
                        break;
                    case 4:
                        ret.AuthTime = next.ReadChildGeneralizedTime();
                        break;
                    case 5:
                        ret.StartTime = next.ReadChildGeneralizedTime();
                        break;
                    case 6:
                        ret.EndTime = next.ReadChildGeneralizedTime();
                        break;
                    case 7:
                        ret.RenewTill = next.ReadChildGeneralizedTime();
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

//        key[0] EncryptionKey,
//prealm[1] Realm OPTIONAL,
//pname[2] PrincipalName OPTIONAL,
//flags[3] TicketFlags OPTIONAL,
//authtime[4] KerberosTime OPTIONAL,
//starttime[5] KerberosTime OPTIONAL,
//endtime[6] KerberosTime OPTIONAL,
//renew-till[7] KerberosTime OPTIONAL,
//        srealm[8] Realm OPTIONAL,
//        sname[9] PrincipalName OPTIONAL,
//        caddr[10] HostAddresses OPTIONAL
    }
}
