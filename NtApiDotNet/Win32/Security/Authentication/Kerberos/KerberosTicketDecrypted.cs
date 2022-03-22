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
using NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
#pragma warning disable 1591
    /// <summary>
    /// Flags for a Kerberos Ticket.
    /// </summary>
    [Flags]
    public enum KerberosTicketFlags : uint
    {
        None = 0,
        Reserved = 0x1,
        Forwardable = 0x2,
        Forwarded = 0x4,
        Proxiable = 0x8,
        Proxy = 0x10,
        MayPostDate = 0x20,
        PostDated = 0x40,
        Invalid = 0x80,
        Renewable = 0x100,
        Initial = 0x200,
        PreAuthent = 0x400,
        HwAuthent = 0x800,
        TransitedPolicyChecked = 0x1000,
        OkAsDelegate = 0x2000,
        Reserved2 = 0x4000,
        EncPARep = 0x8000,
        Anonymous = 0x10000,
    }
#pragma warning restore 1591

    /// <summary>
    /// Class to represent a Decrypted Kerberos ticket.
    /// </summary>
    public sealed class KerberosTicketDecrypted : KerberosTicket
    {
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
        /// The kerberos session key.
        /// </summary>
        public KerberosAuthenticationKey Key { get; private set; }
        /// <summary>
        /// The ticket transited type information.
        /// </summary>
        public KerberosTransitedEncoding TransitedType { get; private set; }
        /// <summary>
        /// List of host addresses for ticket.
        /// </summary>
        public IReadOnlyList<KerberosHostAddress> HostAddresses { get; private set; }
        /// <summary>
        /// List of authorization data.
        /// </summary>
        public IReadOnlyList<KerberosAuthorizationData> AuthorizationData { get; private set; }

        /// <summary>
        /// Create a builder object from this ticket.
        /// </summary>
        /// <returns></returns>
        public KerberosTicketBuilder ToBuilder()
        {
            return new KerberosTicketBuilder(TicketVersion, Realm, ServerName, Flags, ClientRealm, ClientName,
                AuthTime, StartTime, EndTime, RenewTill, Key, TransitedType, HostAddresses, AuthorizationData);
        }

        private protected override void FormatTicketData(StringBuilder builder)
        {
            builder.AppendLine($"Flags           : {Flags}");
            builder.AppendLine($"Client Name     : {ClientName}");
            builder.AppendLine($"Client Realm    : {ClientRealm}");
            if (AuthTime != null)
            {
                builder.AppendLine($"Auth Time       : {AuthTime.ToDateTime()}");
            }
            if (StartTime != null)
            {
                builder.AppendLine($"Start Time      : {StartTime.ToDateTime()}");
            }
            if (EndTime != null)
            {
                builder.AppendLine($"End Time        : {EndTime.ToDateTime()}");
            }
            if (RenewTill != null)
            {
                builder.AppendLine($"Renew Till Time : {RenewTill.ToDateTime()}");
            }
            builder.AppendLine();
            if (Key != null)
            {
                builder.AppendLine("<Session Key>");
                builder.AppendLine($"Encryption Type : {Key.KeyEncryption}");
                builder.AppendLine($"Encryption Key  : {NtObjectUtils.ToHexString(Key.Key)}");
                builder.AppendLine();
            }
            if (TransitedType != null && TransitedType.Data.Length > 0)
            {
                builder.AppendLine($"<Transited Type - {TransitedType.TransitedType}>");
                builder.AppendLine($"{NtObjectUtils.ToHexString(TransitedType.Data)}");
                builder.AppendLine();
            }
            if (HostAddresses?.Count > 0)
            {
                builder.AppendLine("<Host Addresses>");
                foreach (var addr in HostAddresses)
                {
                    builder.AppendLine(addr.ToString());
                }
                builder.AppendLine();
            }
            if (AuthorizationData?.Count > 0)
            {
                foreach (var ad in AuthorizationData)
                {
                    ad.Format(builder);
                }
                builder.AppendLine();
            }
        }

        private KerberosTicketDecrypted(KerberosTicket ticket, byte[] decrypted) 
            : base(ticket.TicketVersion, ticket.Realm, ticket.ServerName, 
                  KerberosEncryptedData.Create(KerberosEncryptionType.NULL, decrypted))
        {
        }

        internal static bool Parse(KerberosTicket orig_ticket, byte[] decrypted, KerberosKeySet keyset, out KerberosTicket ticket)
        {
            ticket = null;
            try
            {
                DERValue[] values = DERParser.ParseData(decrypted, 0);
                if (values.Length != 1)
                    return false;
                DERValue value = values[0];
                if (!value.CheckApplication(3) || !value.HasChildren())
                    return false;
                if (!value.Children[0].CheckSequence())
                    return false;
                var ret = new KerberosTicketDecrypted(orig_ticket, decrypted);
                foreach (var next in value.Children[0].Children)
                {
                    if (next.Type != DERTagType.ContextSpecific)
                        return false;
                    switch (next.Tag)
                    {
                        case 0:
                            ret.Flags = next.ReadChildBitFlags<KerberosTicketFlags>();
                            break;
                        case 1:
                            if (!next.HasChildren())
                                return false;
                            ret.Key = KerberosAuthenticationKey.Parse(next.Children[0], orig_ticket.Realm, orig_ticket.ServerName);
                            keyset.Add(ret.Key);
                            break;
                        case 2:
                            ret.ClientRealm = next.ReadChildGeneralString();
                            break;
                        case 3:
                            if (!next.Children[0].CheckSequence())
                                return false;
                            ret.ClientName = KerberosPrincipalName.Parse(next.Children[0]);
                            break;
                        case 4:
                            if (!next.HasChildren())
                                return false;
                            ret.TransitedType = KerberosTransitedEncoding.Parse(next.Children[0]);
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
                            if (!next.HasChildren())
                                return false;
                            ret.HostAddresses = KerberosHostAddress.ParseSequence(next.Children[0]);
                            break;
                        case 10:
                            if (!next.HasChildren())
                                return false;
                            ret.AuthorizationData = KerberosAuthorizationData.ParseSequence(next.Children[0]);
                            break;
                        default:
                            return false;
                    }
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
