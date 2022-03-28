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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Represents a KDC-REP authentication token.
    /// </summary>
    public sealed class KerberosKDCReplyAuthenticationToken : KerberosAuthenticationToken
    {
        #region Public Properties
        /// <summary>
        /// List of pre-authentication data.
        /// </summary>
        public IReadOnlyList<KerberosPreAuthenticationData> PreAuthenticationData { get; private set; }
        /// <summary>
        /// The client's realm.
        /// </summary>
        public string ClientRealm { get; private set; }
        /// <summary>
        /// The client name.
        /// </summary>
        public KerberosPrincipalName ClientName { get; private set; }
        /// <summary>
        /// The Keberos ticket.
        /// </summary>
        public KerberosTicket Ticket { get; private set; }
        /// <summary>
        /// Encrypted data.
        /// </summary>
        public KerberosEncryptedData EncryptedData { get; private set; }
        #endregion

        #region Public Static Members
        /// <summary>
        /// Try and parse a KDC-REP token.
        /// </summary>
        /// <param name="data">The token in DER format.</param>
        /// <param name="token">The parsed token.</param>
        /// <returns>Returns true if successfully parsed.</returns>
        public static bool TryParse(byte[] data, out KerberosKDCReplyAuthenticationToken token)
        {
            token = null;
            try
            {
                bool result = TryParse(data, DERParser.ParseData(data, 0), out KerberosAuthenticationToken reply);
                token = (KerberosKDCReplyAuthenticationToken)reply;
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
        new public static KerberosKDCReplyAuthenticationToken Parse(byte[] data)
        {
            if (!TryParse(data, out KerberosKDCReplyAuthenticationToken token))
            {
                throw new InvalidDataException("Invalid KDC-REP data structure.");
            }
            return token;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Create a builder for this token.
        /// </summary>
        /// <returns>The builder object.</returns>
        public KerberosKDCReplyBuilder ToBuilder()
        {
            KerberosKDCReplyBuilder builder;
            if (MessageType == KerberosMessageType.KRB_AS_REP)
            {
                builder = new KerberosASReplyBuilder();
            }
            else
            {
                builder = new KerberosTGSReplyBuilder();
            }

            builder.PreAuthenticationData = PreAuthenticationData?.ToList();
            builder.ClientName = ClientName;
            builder.ClientRealm = ClientRealm;
            builder.Ticket = Ticket;
            builder.EncryptedData = EncryptedData;

            return builder;
        }
        #endregion

        #region Internal Members
        internal static bool TryParse(byte[] data, DERValue[] values, out KerberosAuthenticationToken token)
        {
            token = null;
            try
            {
                if (values.Length != 1 || !values[0].HasChildren())
                    return false;

                if (!values[0].CheckMsg(KerberosMessageType.KRB_AS_REP) && !values[0].CheckMsg(KerberosMessageType.KRB_TGS_REP))
                {
                    return false;
                }

                var ret = new KerberosKDCReplyAuthenticationToken(data, values, (KerberosMessageType)values[0].Tag);

                values = values[0].Children;
                if (values.Length != 1 || !values[0].CheckSequence() || !values[0].HasChildren())
                    return false;

                foreach (var next in values[0].Children)
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
                            KerberosMessageType type = (KerberosMessageType)next.ReadChildInteger();
                            if (type != ret.MessageType)
                                return false;
                            break;
                        case 2:
                            ret.PreAuthenticationData = next.ReadChildSequence(v => KerberosPreAuthenticationData.Parse(v)).AsReadOnly();
                            break;
                        case 3:
                            ret.ClientRealm = next.ReadChildGeneralString();
                            break;
                        case 4:
                            ret.ClientName = next.ReadChildPrincipalName();
                            break;
                        case 5:
                            ret.Ticket = next.ReadChildTicket();
                            break;
                        case 6:
                            ret.EncryptedData = next.ReadChildEncryptedData();
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

        internal static KerberosKDCReplyAuthenticationToken Create(KerberosMessageType message_type, IEnumerable<KerberosPreAuthenticationData> pre_auth_data,
            string client_realm, KerberosPrincipalName client_name, KerberosTicket ticket, KerberosEncryptedData encrypted_data)
        {
            if (client_realm is null)
            {
                throw new ArgumentNullException(nameof(client_realm));
            }

            if (client_name is null)
            {
                throw new ArgumentNullException(nameof(client_name));
            }

            if (ticket is null)
            {
                throw new ArgumentNullException(nameof(ticket));
            }

            if (encrypted_data is null)
            {
                throw new ArgumentNullException(nameof(encrypted_data));
            }

            DERBuilder builder = new DERBuilder();
            using (var app = builder.CreateMsg(message_type))
            {
                using (var seq = app.CreateSequence())
                {
                    seq.WriteKerberosHeader(message_type);
                    if ((pre_auth_data != null) && pre_auth_data.Any())
                    {
                        seq.WriteContextSpecific(2, pre_auth_data);
                    }
                    seq.WriteContextSpecific(3, client_realm);
                    seq.WriteContextSpecific(4, client_name);
                    seq.WriteContextSpecific(5, ticket);
                    seq.WriteContextSpecific(6, encrypted_data);
                }
            }

            return Parse(builder.ToArray());
        }

        #endregion

        #region Private Members
        private KerberosKDCReplyAuthenticationToken(byte[] data, DERValue[] values, KerberosMessageType message_type)
                : base(data, values, message_type)
        {
        }
        #endregion
    }
}
