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
using System.Linq;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent a Decrypted Kerberos ticket.
    /// </summary>
    public sealed class KerberosTicketDecrypted : KerberosTicket
    {
        #region Public Properties
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
        #endregion

        #region Public Methods
        /// <summary>
        /// Create a builder object from this ticket.
        /// </summary>
        /// <returns></returns>
        public KerberosTicketBuilder ToBuilder()
        {
            return new KerberosTicketBuilder(TicketVersion, Realm, ServerName, Flags, ClientRealm, ClientName,
                AuthTime, StartTime, EndTime, RenewTill, Key, TransitedType, HostAddresses, AuthorizationData);
        }

        /// <summary>
        /// Find the PAC for the ticket.
        /// </summary>
        /// <returns>The PAC for the ticket. Returns null if no PAC present.</returns>
        public KerberosAuthorizationDataPAC FindPAC()
        {
            return AuthorizationData.FindAuthorizationData<KerberosAuthorizationDataPAC>(KerberosAuthorizationDataType.AD_WIN2K_PAC);
        }

        /// <summary>
        /// Find a list of auth data for a specific AD type.
        /// </summary>
        /// <param name="data_type">The AD type.</param>
        /// <returns>The list of auth data. And empty list if not found.</returns>
        public IEnumerable<KerberosAuthorizationData> FindAuthorizationData(KerberosAuthorizationDataType data_type)
        {
            return AuthorizationData.FindAllAuthorizationData<KerberosAuthorizationData>(data_type);
        }

        /// <summary>
        /// Find the first auth data for a specific AD type.
        /// </summary>
        /// <param name="data_type">The AD type.</param>
        /// <returns>The first auth data. Returns null if not found.</returns>
        public KerberosAuthorizationData FindFirstAuthorizationData(KerberosAuthorizationDataType data_type)
        {
            return FindAuthorizationData(data_type).FirstOrDefault();
        }

        /// <summary>
        /// Create a credential info structure for this ticket.
        /// </summary>
        /// <returns>The ticket's credential info.</returns>
        public KerberosCredentialInfo ToCredentialInfo()
        {
            return new KerberosCredentialInfo(Key, ClientRealm, ClientName, Flags, AuthTime, StartTime, EndTime, RenewTill, Realm, ServerName, HostAddresses);
        }

        /// <summary>
        /// Validate the KDC ticket signature in the PAC.
        /// </summary>
        /// <param name="key">The KDC key.</param>
        /// <returns>True if the signature is correct. Also assumes true if there are no signature to check.</returns>
        public bool ValidateTicketSignature(KerberosAuthenticationKey key)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            var sig_left = FindPAC()?.Entries.FirstOrDefault(e => e.PACType == KerberosAuthorizationDataPACEntryType.TicketChecksum);
            if (sig_left == null)
                return true;
            
            var builder = ToBuilder();
            builder.ComputeTicketSignature(key);
            var result = builder.Create();
            var sig_right = result.FindPAC().Entries.FirstOrDefault(e => e.PACType == KerberosAuthorizationDataPACEntryType.TicketChecksum);
            System.Diagnostics.Debug.Assert(sig_right != null);
            return sig_left.Equals(sig_right);
        }

        #endregion

        #region Private Members
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

        //private static T FindAuthorizationData<T>(
        //    IEnumerable<KerberosAuthorizationData> auth_data,
        //    KerberosAuthorizationDataType type) where T : KerberosAuthorizationData
        //{
        //    List<KerberosAuthorizationData> list = new List<KerberosAuthorizationData>();
        //    FindAuthorizationData(list, auth_data, type);
        //    return list.OfType<T>().FirstOrDefault();
        //}

        //private static void FindAuthorizationData(
        //    List<KerberosAuthorizationData> list,
        //    IEnumerable<KerberosAuthorizationData> auth_data,
        //    KerberosAuthorizationDataType type)
        //{
        //    if (auth_data == null)
        //        return;
        //    foreach (var next in auth_data)
        //    {
        //        if (next.DataType == type)
        //            list.Add(next);
        //        if (next is KerberosAuthorizationDataIfRelevant if_rel)
        //        {
        //            FindAuthorizationData(list, if_rel.Entries, type);
        //        }
        //    }
        //    return;
        //}

        private KerberosTicketDecrypted(KerberosTicket ticket, byte[] decrypted) 
            : base(ticket.TicketVersion, ticket.Realm, ticket.ServerName, 
                  KerberosEncryptedData.Create(KerberosEncryptionType.NULL, decrypted))
        {
        }
        #endregion

        #region Internal Members
        internal static bool Parse(KerberosTicket orig_ticket, byte[] decrypted, KerberosKeySet keyset, out KerberosTicketDecrypted ticket)
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
        #endregion
    }
}
