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
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent a User to User TGT Reply.
    /// </summary>
    public class KerberosTGTReplyAuthenticationToken : KerberosAuthenticationToken
    {
        /// <summary>
        /// Protocol version.
        /// </summary>
        public int ProtocolVersion { get; }
        /// <summary>
        /// Message type.
        /// </summary>
        public KRB_MSG_TYPE MessageType { get; }
        /// <summary>
        /// The Kerberos Ticket.
        /// </summary>
        public KerberosTicket Ticket { get; private set; }

        private protected KerberosTGTReplyAuthenticationToken(byte[] data, DERValue[] values)
            : base(data, values)
        {
            ProtocolVersion = 5;
            MessageType = KRB_MSG_TYPE.KRB_TGT_REP;
        }

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

                Queue<DERValue> queue = new Queue<DERValue>(values[0].Children);
                while (queue.Count > 0)
                {
                    var next = queue.Dequeue();
                    if (next.Type != DERTagType.ContextSpecific)
                        return false;
                    switch (next.Tag)
                    {
                        case 0:
                            if (next.ReadChildInteger() != 5)
                                return false;
                            break;
                        case 1:
                            if ((KRB_MSG_TYPE)next.ReadChildInteger() != KRB_MSG_TYPE.KRB_TGT_REP)
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
