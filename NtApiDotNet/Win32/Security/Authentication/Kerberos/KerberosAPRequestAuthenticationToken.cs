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
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Options for AP Request
    /// </summary>
    [Flags]
    public enum KerberosAPRequestOptions
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
    public class KerberosAPRequestAuthenticationToken : KerberosAuthenticationToken
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

        private protected KerberosAPRequestAuthenticationToken(byte[] data, DERValue[] values)
            : base(data, values)
        {
            ProtocolVersion = 5;
            MessageType = KRB_MSG_TYPE.KRB_AP_REQ;
            Ticket = new KerberosTicket();
            Authenticator = new KerberosEncryptedData();
        }

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
                            if ((KRB_MSG_TYPE)next.ReadChildInteger() != KRB_MSG_TYPE.KRB_AP_REQ)
                                return false;
                            break;
                        case 2:
                            if (!next.Children[0].CheckPrimitive(UniversalTag.BIT_STRING))
                            {
                                return false;
                            }
                            var bits = next.Children[0].ReadBitString();
                            var options = KerberosAPRequestOptions.None;
                            if (bits[1])
                                options |= KerberosAPRequestOptions.UseSessionKey;
                            if (bits[2])
                                options |= KerberosAPRequestOptions.MutualAuthRequired;
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
                            ret.Authenticator = KerberosEncryptedData.Parse(next.Children[0]);
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
