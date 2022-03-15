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
    /// Represents a KDC-REQ authentication token.
    /// </summary>
    public sealed class KerberosKDCRequestAuthenticationToken : KerberosAuthenticationToken
    {
        #region Internal Members
        internal KerberosKDCRequestAuthenticationToken(byte[] data, DERValue[] values, KerberosMessageType message_type) 
            : base(data, values, message_type)
        {
        }
        #endregion

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
                DERValue[] values = DERParser.ParseData(data, 0);

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
                        ret.AdditionalTickets = next.ReadChildSequence(v => v.ReadChildTicket()).AsReadOnly();
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
