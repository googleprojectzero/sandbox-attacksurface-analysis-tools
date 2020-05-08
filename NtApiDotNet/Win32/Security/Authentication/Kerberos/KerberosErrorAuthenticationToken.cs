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
using NtApiDotNet.Utilities.Text;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent a Kerberos Error.
    /// </summary>
    public class KerberosErrorAuthenticationToken : KerberosAuthenticationToken
    {
        /// <summary>
        /// Client time.
        /// </summary>
        public string ClientTime { get; private set; }
        /// <summary>
        /// Client micro-seconds.
        /// </summary>
        public int ClientUSec { get; private set; }
        /// <summary>
        /// Server time.
        /// </summary>
        public string ServerTime { get; private set; }
        /// <summary>
        /// Server micro-seconds.
        /// </summary>
        public int ServerUSec { get; private set; }
        /// <summary>
        /// Error code.
        /// </summary>
        public KerberosErrorType ErrorCode { get; private set; }
        /// <summary>
        /// Client realm.
        /// </summary>
        public string ClientRealm { get; private set; }
        /// <summary>
        /// Client name.
        /// </summary>
        public KerberosPrincipalName ClientName { get; private set; }
        /// <summary>
        /// Server realm.
        /// </summary>
        public string ServerRealm { get; private set; }
        /// <summary>
        /// Server name,
        /// </summary>
        public KerberosPrincipalName ServerName { get; private set; }
        /// <summary>
        /// Error text.
        /// </summary>
        public string ErrorText { get; private set; }
        /// <summary>
        /// Error data.
        /// </summary>
        public byte[] ErrorData { get; private set; }

        private protected KerberosErrorAuthenticationToken(byte[] data, DERValue[] values)
            : base(data, values, KerberosMessageType.KRB_ERROR)
        {
            ClientRealm = string.Empty;
            ClientName = new KerberosPrincipalName();
            ClientTime = string.Empty;
            ServerRealm = string.Empty;
            ServerName = new KerberosPrincipalName();
            ServerTime = string.Empty;
            ErrorText = string.Empty;
            ErrorData = new byte[0];
        }

        /// <summary>
        /// Format the Authentication Token.
        /// </summary>
        /// <returns>The Formatted Token.</returns>
        public override string Format()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine($"<KerberosV{ProtocolVersion} {MessageType}>");
            if (!string.IsNullOrEmpty(ClientTime))
            {
                builder.AppendLine($"Client Time       : {KerberosUtils.ParseKerberosTime(ClientTime, ClientUSec)}");
            }
            if (!string.IsNullOrEmpty(ClientRealm))
            {
                builder.AppendLine($"Client Realm       : {ClientRealm}");
                builder.AppendLine($"Client Name        : {ClientName}");
            }

            builder.AppendLine($"Server Time       : {KerberosUtils.ParseKerberosTime(ServerTime, ServerUSec)}");
            builder.AppendLine($"Server Realm      : {ServerRealm}");
            builder.AppendLine($"Server Name       : {ServerName}");
            builder.AppendLine($"Error Code        : {ErrorCode}");
            if (!string.IsNullOrEmpty(ErrorText))
                builder.AppendLine($"Error Text        : {ErrorText}");
            if (ErrorData.Length > 0)
            {
                builder.AppendLine($"Error Data        :");
                HexDumpBuilder hex = new HexDumpBuilder();
                hex.Append(ErrorData);
                hex.Complete();
                builder.Append(hex);
            }

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
                var ret = new KerberosErrorAuthenticationToken(data, values);

                if (values.Length != 1 || !values[0].CheckMsg(KerberosMessageType.KRB_ERROR) || !values[0].HasChildren())
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
                            if ((KerberosMessageType)next.ReadChildInteger() != KerberosMessageType.KRB_ERROR)
                                return false;
                            break;
                        case 2:
                            ret.ClientTime = next.ReadChildGeneralizedTime();
                            break;
                        case 3:
                            ret.ClientUSec = next.ReadChildInteger();
                            break;
                        case 4:
                            ret.ServerTime = next.ReadChildGeneralizedTime();
                            break;
                        case 5:
                            ret.ServerUSec = next.ReadChildInteger();
                            break;
                        case 6:
                            ret.ErrorCode = (KerberosErrorType)next.ReadChildInteger();
                            break;
                        case 7:
                            ret.ClientRealm = next.ReadChildGeneralString();
                            break;
                        case 8:
                            if (!next.Children[0].CheckSequence())
                            {
                                throw new InvalidDataException();
                            }
                            ret.ClientName = KerberosPrincipalName.Parse(next.Children[0]);
                            break;
                        case 9:
                            ret.ServerRealm = next.ReadChildGeneralString();
                            break;
                        case 10:
                            if (!next.Children[0].CheckSequence())
                            {
                                throw new InvalidDataException();
                            }
                            ret.ServerName = KerberosPrincipalName.Parse(next.Children[0]);
                            break;
                        case 11:
                            ret.ErrorText = next.ReadChildGeneralString();
                            break;
                        case 12:
                            ret.ErrorData = next.ReadChildOctetString();
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
