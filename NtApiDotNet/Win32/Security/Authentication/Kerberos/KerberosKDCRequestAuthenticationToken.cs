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
using NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Represents a KDC-REQ authentication token.
    /// </summary>
    public sealed class KerberosKDCRequestAuthenticationToken : KerberosAuthenticationToken
    {
        #region Public Properties
        /// <summary>
        /// List of pre-authentication data.
        /// </summary>
        public IReadOnlyList<KerberosPreAuthenticationData> PreAuthenticationData { get; private set; }
        /// <summary>
        /// The KDC options flags.
        /// </summary>
        public KerberosKDCOptions KDCOptions { get; private set; }
        /// <summary>
        /// The client name.
        /// </summary>
        public KerberosPrincipalName ClientName { get; private set; }
        /// <summary>
        /// The server and/or client's realm.
        /// </summary>
        public string Realm { get; private set; }
        /// <summary>
        /// The server name.
        /// </summary>
        public KerberosPrincipalName ServerName { get; private set; }
        /// <summary>
        /// The from valid time.
        /// </summary>
        public KerberosTime FromTime { get; private set; }
        /// <summary>
        /// The time valid time.
        /// </summary>
        public KerberosTime TillTime { get; private set; }
        /// <summary>
        /// The renew till time.
        /// </summary>
        public KerberosTime RenewTill { get; private set; }
        /// <summary>
        /// The nonce.
        /// </summary>
        public int Nonce { get; private set; }
        /// <summary>
        /// List of supported encryption types.
        /// </summary>
        public IReadOnlyList<KerberosEncryptionType> EncryptionTypes { get; private set; }
        /// <summary>
        /// List of host addresses.
        /// </summary>
        public IReadOnlyList<KerberosHostAddress> Addresses { get; private set; }
        /// <summary>
        /// Encrypted authorization data.
        /// </summary>
        public KerberosEncryptedData AuthorizationData { get; private set; }
        /// <summary>
        /// List of additional tickets.
        /// </summary>
        public IReadOnlyList<KerberosTicket> AdditionalTickets { get; private set; }
        #endregion

        #region Public Methods
        /// <summary>
        /// Format the Authentication Token.
        /// </summary>
        /// <returns>The Formatted Token.</returns>
        public override string Format()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine($"<KerberosV{ProtocolVersion} {MessageType}>");
            if (!PreAuthenticationData.IsEmpty())
            {
                builder.AppendLine("<Pre Authentication Data>");
                foreach (var pa_data in PreAuthenticationData)
                {
                    builder.AppendLine(pa_data.Format());
                }
                builder.AppendLine("</Pre Authentication Data>");
            }
            builder.AppendLine($"KDC Options     : {KDCOptions}");
            if (ClientName != null)
            {
                builder.AppendLine($"Client Name     : {ClientName}");
            }
            builder.AppendLine($"Realm           : {Realm}");
            if (ServerName != null)
            {
                builder.AppendLine($"Server Name     : {ServerName}");
            }
            if (FromTime != null)
            {
                builder.AppendLine($"From Time       : {FromTime}");
            }
            builder.AppendLine($"Till Time       : {TillTime}");
            if (RenewTill != null)
            {
                builder.AppendLine($"Renew Time      : {RenewTill}");
            }
            builder.AppendLine($"Nonce           : 0x{Nonce:X08}");
            builder.AppendLine($"Encryption Types: {string.Join(", ", EncryptionTypes)}");
            if (!Addresses.IsEmpty())
            {
                builder.AppendLine($"Addresses       : {string.Join(", ", Addresses)}");
            }

            if (AuthorizationData != null)
            {
                builder.AppendLine("Auth Data       :");
                builder.AppendLine(AuthorizationData.Format());
            }
            if (!AdditionalTickets.IsEmpty())
            {
                foreach (var ticket in AdditionalTickets)
                {
                    builder.Append(ticket.Format());
                }
            }
            return builder.ToString();
        }

        /// <summary>
        /// Create a builder for this token.
        /// </summary>
        /// <returns>The builder object.</returns>
        public KerberosKDCRequestBuilder ToBuilder()
        {
            KerberosKDCRequestBuilder builder;
            if (MessageType == KerberosMessageType.KRB_AS_REQ)
            {
                builder = new KerberosASRequestBuilder();
            }
            else
            {
                builder = new KerberosTGSRequestBuilder();
            }
            builder.PreAuthenticationData = PreAuthenticationData?.ToList();
            builder.KDCOptions = KDCOptions;
            builder.ClientName = ClientName;
            builder.Nonce = Nonce;
            builder.Realm = Realm;
            builder.ServerName = ServerName;
            builder.FromTime = FromTime;
            builder.TillTime = TillTime;
            builder.RenewTill = RenewTill;
            builder.EncryptionTypes = EncryptionTypes?.ToList();
            builder.Addresses = Addresses?.ToList();
            builder.AuthorizationData = AuthorizationData;
            builder.AdditionalTickets = AdditionalTickets?.ToList();
            return builder;
        }
        #endregion

        #region Public Static Members
        /// <summary>
        /// Try and parse a KDC-REQ token.
        /// </summary>
        /// <param name="data">The token in DER format.</param>
        /// <param name="token">The parsed token.</param>
        /// <returns>Returns true if successfully parsed.</returns>
        public static bool TryParse(byte[] data, out KerberosKDCRequestAuthenticationToken token)
        {
            token = null;
            try
            {
                bool result = TryParse(data, DERParser.ParseData(data, 0), out KerberosAuthenticationToken tmp);
                token = (KerberosKDCRequestAuthenticationToken)tmp;
                return result;
            }
            catch (InvalidDataException)
            {
            }

            return false;
        }

        /// <summary>
        /// Parse a KDC-REQ token.
        /// </summary>
        /// <param name="data">The token in DER format.</param>
        /// <returns>The parsed token.</returns>
        new public static KerberosKDCRequestAuthenticationToken Parse(byte[] data)
        {
            if (!TryParse(data, out KerberosKDCRequestAuthenticationToken token))
            {
                throw new InvalidDataException("Invalid KDC-REQ data structure.");
            }
            return token;
        }
        #endregion

        #region Private Members
        private KerberosKDCRequestAuthenticationToken(byte[] data, DERValue[] values, KerberosMessageType message_type)
            : base(data, values, message_type)
        {
        }
        #endregion

        #region Internal Members
        internal static void EncodeBody(DERBuilder builder, string realm, KerberosTime till_time, int nonce, 
            IEnumerable<KerberosEncryptionType> encryption_type, KerberosKDCOptions options, KerberosPrincipalName client_name,
            KerberosPrincipalName server_name, KerberosTime from_time, KerberosTime renew_till,
            IEnumerable<KerberosHostAddress> addresses, KerberosEncryptedData enc_authorization_data,
            IEnumerable<KerberosTicket> additional_tickets)
        {
            if (realm is null)
            {
                throw new ArgumentNullException(nameof(realm));
            }

            if (till_time is null)
            {
                throw new ArgumentNullException(nameof(till_time));
            }

            using (var body = builder.CreateSequence())
            {
                body.WriteContextSpecific(0, b => b.WriteBitString(options));
                body.WriteContextSpecific(1, client_name);
                body.WriteContextSpecific(2, realm);
                body.WriteContextSpecific(3, server_name);
                body.WriteContextSpecific(4, from_time);
                body.WriteContextSpecific(5, till_time);
                body.WriteContextSpecific(6, renew_till);
                body.WriteContextSpecific(7, nonce);
                body.WriteContextSpecific(8, b => b.WriteSequence(encryption_type, (r, i) => r.WriteInt32((int)i)));
                body.WriteContextSpecific(9, addresses);
                body.WriteContextSpecific(10, enc_authorization_data);
                body.WriteContextSpecific(11, additional_tickets);
            }
        }

        internal static KerberosKDCRequestAuthenticationToken Create(KerberosMessageType type,
            string realm, KerberosTime till_time, int nonce, IEnumerable<KerberosEncryptionType> encryption_type, 
            KerberosKDCOptions options, IEnumerable<KerberosPreAuthenticationData> pre_auth_data, KerberosPrincipalName client_name,
            KerberosPrincipalName server_name, KerberosTime from_time, KerberosTime renew_till,
            IEnumerable<KerberosHostAddress> addresses, KerberosEncryptedData enc_authorization_data,
            IEnumerable<KerberosTicket> additional_tickets)
        {
            DERBuilder builder = new DERBuilder();
            using (var app = builder.CreateMsg(type))
            {
                using (var seq = app.CreateSequence())
                {
                    seq.WriteContextSpecific(1, 5);
                    seq.WriteContextSpecific(2, (int)type);
                    if ((pre_auth_data != null) && pre_auth_data.Any())
                    {
                        seq.WriteContextSpecific(3, pre_auth_data);
                    }
                    using (var ctx = seq.CreateContextSpecific(4))
                    {
                        EncodeBody(ctx, realm, till_time, nonce, encryption_type, options, client_name, server_name,
                            from_time, renew_till, addresses, enc_authorization_data, additional_tickets);
                    }
                }
            }

            return Parse(builder.ToArray());
        }

        internal static bool TryParse(byte[] data, DERValue[] values, out KerberosAuthenticationToken token)
        {
            token = null;
            try
            {
                if (values.Length != 1 || !values[0].HasChildren())
                    return false;

                if (!values[0].CheckMsg(KerberosMessageType.KRB_AS_REQ) && !values[0].CheckMsg(KerberosMessageType.KRB_TGS_REQ))
                {
                    return false;
                }

                KerberosKDCRequestAuthenticationToken ret = new KerberosKDCRequestAuthenticationToken(data, values, (KerberosMessageType)values[0].Tag);

                values = values[0].Children;
                if (values.Length != 1 || !values[0].CheckSequence() || !values[0].HasChildren())
                    return false;

                foreach (var next in values[0].Children)
                {
                    if (next.Type != DERTagType.ContextSpecific)
                        return false;
                    switch (next.Tag)
                    {
                        case 1:
                            if (next.ReadChildInteger() != 5)
                                return false;
                            break;
                        case 2:
                            KerberosMessageType type = (KerberosMessageType)next.ReadChildInteger();
                            if (type != ret.MessageType)
                                return false;
                            break;
                        case 3:
                            ret.PreAuthenticationData = next.ReadChildSequence(v => KerberosPreAuthenticationData.Parse(v)).AsReadOnly();
                            break;
                        case 4:
                            if (!next.Children[0].CheckSequence())
                            {
                                return false;
                            }
                            if (!TryParseRequestBody(next.Children[0], ret))
                                return false;
                            break;
                        default:
                            return false;
                    }
                }
                token = ret;
                return true;
            }
            catch (InvalidDataException)
            {
            }
            return false;
        }

        private static bool TryParseRequestBody(DERValue value, KerberosKDCRequestAuthenticationToken ret)
        {
            foreach (var next in value.Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    return false;
                switch (next.Tag)
                {
                    case 0:
                        ret.KDCOptions = next.ReadChildBitFlags<KerberosKDCOptions>();
                        break;
                    case 1:
                        ret.ClientName = next.ReadChildPrincipalName();
                        break;
                    case 2:
                        ret.Realm = next.ReadChildGeneralString();
                        break;
                    case 3:
                        ret.ServerName = next.ReadChildPrincipalName();
                        break;
                    case 4:
                        ret.FromTime = next.ReadChildKerberosTime();
                        break;
                    case 5:
                        ret.TillTime = next.ReadChildKerberosTime();
                        break;
                    case 6:
                        ret.RenewTill = next.ReadChildKerberosTime();
                        break;
                    case 7:
                        ret.Nonce = next.ReadChildInteger();
                        break;
                    case 8:
                        ret.EncryptionTypes = next.ReadChildEnumSequence<KerberosEncryptionType>().AsReadOnly();
                        break;
                    case 9:
                        ret.Addresses = KerberosHostAddress.ParseSequence(next.Children[0]);
                        break;
                    case 10:
                        ret.AuthorizationData = next.ReadChildEncryptedData();
                        break;
                    case 11:
                        ret.AdditionalTickets = next.ReadChildSequence(v => KerberosTicket.Parse(v)).AsReadOnly();
                        break;
                    default:
                        return false;
                }
            }

            return true;
        }
        #endregion
    }
}
