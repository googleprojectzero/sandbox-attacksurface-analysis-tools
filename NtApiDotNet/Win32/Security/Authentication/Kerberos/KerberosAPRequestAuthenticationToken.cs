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
using NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Options for AP Request
    /// </summary>
    [Flags]
    public enum KerberosAPRequestOptions : uint
    {
        /// <summary>
        /// None.
        /// </summary>
        None = 0,
        /// <summary>
        /// Use Session Key.
        /// </summary>
        UseSessionKey = 1,
        /// <summary>
        /// Mutual authentication required.
        /// </summary>
        MutualAuthRequired = 2,
    }

    /// <summary>
    /// Class to represent a Kerberos AP Request.
    /// </summary>
    public sealed class KerberosAPRequestAuthenticationToken : KerberosAuthenticationToken
    {
        #region Public Properties
        /// <summary>
        /// AP Request Options.
        /// </summary>
        public KerberosAPRequestOptions Options { get; private set; }
        /// <summary>
        /// The Kerberos Ticket.
        /// </summary>
        public KerberosTicket Ticket { get; private set; }
        /// <summary>
        /// Authenticator data.
        /// </summary>
        public KerberosEncryptedData Authenticator { get; private set; }
        #endregion

        #region Constructors
        private KerberosAPRequestAuthenticationToken(byte[] data, DERValue[] values)
            : base(data, values, KerberosMessageType.KRB_AP_REQ)
        {
            Ticket = new KerberosTicket();
            Authenticator = new KerberosEncryptedData();
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
            builder.AppendLine($"Options         : {Options}");
            builder.AppendLine("<Ticket>");
            builder.Append(Ticket.Format());
            builder.AppendLine("<Authenticator>");
            builder.Append(Authenticator.Format());
            return builder.ToString();
        }

        /// <summary>
        /// Decrypt the Authentication Token using a keyset.
        /// </summary>
        /// <param name="keyset">The set of keys to decrypt the </param>
        /// <returns>The decrypted token, or the same token if nothing could be decrypted.</returns>
        public override AuthenticationToken Decrypt(IEnumerable<AuthenticationKey> keyset)
        {
            KerberosAuthenticator authenticator = null;

            KerberosKeySet tmp_keys = new KerberosKeySet(keyset.OfType<KerberosAuthenticationKey>());
            if (!Ticket.TryDecrypt(tmp_keys, KerberosKeyUsage.AsRepTgsRepTicket, out KerberosTicket ticket))
            {
                ticket = null;
            }

            if (Authenticator.Decrypt(tmp_keys, Ticket.Realm, Ticket.ServerName, KerberosKeyUsage.ApReqAuthSubKey, out byte[] auth_decrypt))
            {
                if (!KerberosAuthenticator.TryParse(Ticket, auth_decrypt, tmp_keys, out authenticator))
                {
                    authenticator = null;
                }
            }

            if (ticket != null || authenticator != null)
            {
                KerberosAPRequestAuthenticationToken ret = (KerberosAPRequestAuthenticationToken)MemberwiseClone();
                ret.Ticket = ticket ?? ret.Ticket;
                ret.Authenticator = authenticator ?? ret.Authenticator;
                return ret;
            }
            return base.Decrypt(keyset);
        }

        #endregion

        #region Public Static Methods
        /// <summary>
        /// Create a new KRB AP-REQ token.
        /// </summary>
        /// <param name="ticket">The service ticket.</param>
        /// <param name="authenticator">The authenticator.</param>
        /// <param name="options">The AP-REQ options.</param>
        /// <param name="authenticator_key">Optional key to encrypt the authenticator.</param>
        /// <param name="authenticator_key_version">Optional key version for authenticator encryption.</param>
        /// <param name="ticket_key">Optional key to encrypt the ticket.</param>
        /// <param name="ticket_key_version">Optional key version for ticket encryption.</param>
        /// <param name="raw_token">Specify to return a raw token without the GSS API header.</param>
        /// <param name="tgs_req">True to indicate this AP-REQ is for a TGS-REP.</param>
        /// <returns>The new AP-REQ token.</returns>
        public static KerberosAPRequestAuthenticationToken Create(KerberosTicket ticket, KerberosEncryptedData authenticator, 
            KerberosAPRequestOptions options = KerberosAPRequestOptions.None, KerberosAuthenticationKey authenticator_key = null, 
            int? authenticator_key_version = null, KerberosAuthenticationKey ticket_key = null, int? ticket_key_version = null, 
            bool raw_token = false, bool tgs_req = false)
        {
            if (ticket is null)
            {
                throw new ArgumentNullException(nameof(ticket));
            }

            if (authenticator is null)
            {
                throw new ArgumentNullException(nameof(authenticator));
            }

            if (ticket_key != null)
            {
                ticket = ticket.Encrypt(ticket_key, KerberosKeyUsage.AsRepTgsRepTicket, ticket_key_version);
            }

            if (authenticator_key != null)
            {
                authenticator = authenticator.Encrypt(authenticator_key, tgs_req ? KerberosKeyUsage.TgsReqPaTgaReqApReq : KerberosKeyUsage.ApReqAuthSubKey, authenticator_key_version);
            }

            DERBuilder builder = new DERBuilder();
            using (var app = builder.CreateApplication(14))
            {
                using (var seq = app.CreateSequence())
                {
                    BitArray option_bits = new BitArray(32, false);
                    option_bits[1] = options.HasFlagSet(KerberosAPRequestOptions.UseSessionKey);
                    option_bits[2] = options.HasFlagSet(KerberosAPRequestOptions.MutualAuthRequired);

                    seq.WriteKerberosHeader(KerberosMessageType.KRB_AP_REQ);
                    seq.WriteContextSpecific(2, b => b.WriteBitString(option_bits));
                    seq.WriteContextSpecific(3, b => b.WriteRawBytes(ticket.ToArray()));
                    seq.WriteContextSpecific(4, authenticator);
                }
            }
            return (KerberosAPRequestAuthenticationToken)Parse(raw_token ? builder.ToArray() : builder.CreateGssApiWrapper(OIDValues.KERBEROS, 0x100));
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
                var ret = new KerberosAPRequestAuthenticationToken(data, values);

                if (values.Length != 1 || !values[0].CheckApplication(14) || !values[0].HasChildren())
                    return false;

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
                            if ((KerberosMessageType)next.ReadChildInteger() != KerberosMessageType.KRB_AP_REQ)
                                return false;
                            break;
                        case 2:
                            if (!next.Children[0].CheckPrimitive(UniversalTag.BIT_STRING))
                            {
                                return false;
                            }
                            var bits = next.Children[0].ReadBitString();
                            var options = KerberosAPRequestOptions.None;
                            if (bits.Length > 2)
                            {
                                if (bits[1])
                                    options |= KerberosAPRequestOptions.UseSessionKey;
                                if (bits[2])
                                    options |= KerberosAPRequestOptions.MutualAuthRequired;
                            }
                            ret.Options = options;
                            break;
                        case 3:
                            if (!next.HasChildren())
                                return false;
                            ret.Ticket = KerberosTicket.Parse(next.Children[0]);
                            break;
                        case 4:
                            if (!next.HasChildren())
                                return false;
                            ret.Authenticator = KerberosEncryptedData.Parse(next.Children[0], next.Data);
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
