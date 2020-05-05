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
        public int TicketVersion { get; }
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

        internal string Format()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine($"Ticket Version  : {TicketVersion}");
            builder.AppendLine($"ServerName      : {ServerName}");
            builder.AppendLine($"Realm           : {Realm}");
            builder.Append(EncryptedData.Format());
            return builder.ToString();
        }

        internal KerberosTicket()
        {
            TicketVersion = 5;
            Realm = string.Empty;
            ServerName = new KerberosPrincipalName();
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
                        if (next.ReadChildInteger() != 5)
                            throw new InvalidDataException();
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
