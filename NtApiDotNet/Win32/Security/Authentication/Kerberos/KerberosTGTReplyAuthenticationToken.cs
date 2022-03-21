﻿//  Copyright 2020 Google Inc. All Rights Reserved.
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
    /// Class to represent a User to User TGT Reply.
    /// </summary>
    public sealed class KerberosTGTReplyAuthenticationToken : KerberosAuthenticationToken
    {
        #region Public Properties
        /// <summary>
        /// The Kerberos Ticket.
        /// </summary>
        public KerberosTicket Ticket { get; private set; }
        #endregion

        #region Private Members
        private KerberosTGTReplyAuthenticationToken(byte[] data, DERValue[] values)
            : base(data, values, KerberosMessageType.KRB_TGT_REP)
        {
        }

        private static DERBuilder CreateBuilder(KerberosTicket ticket)
        {
            if (ticket is null)
            {
                throw new ArgumentNullException(nameof(ticket));
            }

            DERBuilder builder = new DERBuilder();
            using (var seq = builder.CreateSequence())
            {
                seq.WriteKerberosHeader(KerberosMessageType.KRB_TGT_REP);
                seq.WriteContextSpecific(2, ticket);
            }
            return builder;
        }

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
            builder.Append(Ticket.Format());
            return builder.ToString();
        }

        /// <summary>
        /// Decrypt the Authentication Token using a keyset.
        /// </summary>
        /// <param name="keyset">The set of keys to decrypt the </param>
        /// <returns>The decrypted token, or the same token if nothing could be decrypted.</returns>
        public override AuthenticationToken Decrypt(IEnumerable<AuthenticationKey> keyset)
        {
            KerberosEncryptedData authenticator = null;

            KerberosKeySet tmp_keys = new KerberosKeySet(keyset.OfType<KerberosAuthenticationKey>());
            if (!Ticket.TryDecrypt(tmp_keys, KerberosKeyUsage.AsRepTgsRepTicket, out KerberosTicket ticket, out _))
            {
                ticket = null;
            }

            if (ticket != null || authenticator != null)
            {
                var ret = (KerberosTGTReplyAuthenticationToken)MemberwiseClone();
                ret.Ticket = ticket ?? ret.Ticket;
                return ret;
            }
            return base.Decrypt(keyset);
        }
        #endregion

        #region Public Static Members
        /// <summary>
        /// Create a new TGT-REP authentication token.
        /// </summary>
        /// <param name="ticket">The TGT ticket to embed in the token.</param>
        /// <returns>The TGT-REP token.</returns>
        public static KerberosTGTReplyAuthenticationToken Create(KerberosTicket ticket)
        {
            return (KerberosTGTReplyAuthenticationToken)Parse(CreateBuilder(ticket)
                .CreateGssApiWrapper(OIDValues.KERBEROS_USER_TO_USER, 0x401));
        }

        /// <summary>
        /// Create a new TGT-REP authentication token.
        /// </summary>
        /// <param name="ticket">The TGT ticket to embed in the token.</param>
        /// <returns>The TGT-REP token.</returns>
        public static KerberosTGTReplyAuthenticationToken CreateNoGSSAPI(KerberosTicket ticket)
        {
            return (KerberosTGTReplyAuthenticationToken)Parse(CreateBuilder(ticket).ToArray());
        }

        #endregion

        #region Internal Static Methods
        /// <summary>
        /// Try and parse data into an ASN1 authentication token.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <param name="token">The Negotiate authentication token.</param>
        /// <param name="values">Parsed DER Values.</param>
        internal static bool TryParse(byte[] data, DERValue[] values, out KerberosAuthenticationToken token)
        {
            token = null;
            try
            {
                 var ret = new KerberosTGTReplyAuthenticationToken(data, values);

                if (values.Length != 1 || !values[0].HasChildren())
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
                            if ((KerberosMessageType)next.ReadChildInteger() != KerberosMessageType.KRB_TGT_REP)
                                return false;
                            break;
                        case 2:
                            if (!next.HasChildren())
                                return false;
                            ret.Ticket = KerberosTicket.Parse(next.Children[0]);
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
                return false;
            }
        }
        #endregion
    }
}
