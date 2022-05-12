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
using NtApiDotNet.Utilities.Text;
using NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent a Kerberos Error.
    /// </summary>
    public sealed class KerberosErrorAuthenticationToken : KerberosAuthenticationToken
    {
        #region Public Properties
        /// <summary>
        /// Client time.
        /// </summary>
        public KerberosTime ClientTime { get; private set; }
        /// <summary>
        /// Client micro-seconds.
        /// </summary>
        public int ClientUSec { get; private set; }
        /// <summary>
        /// Server time.
        /// </summary>
        public KerberosTime ServerTime { get; private set; }
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
        /// <summary>
        /// The list of parsed error data.
        /// </summary>
        public IReadOnlyList<KerberosErrorData> ErrorDataList { get; private set; }
        /// <summary>
        /// The NT status if extended error data is present.
        /// </summary>
        public NtStatus? Status => ErrorDataList.OfType<KerberosErrorDataExtended>().FirstOrDefault()?.Status;
        #endregion

        #region Private Members
        private KerberosErrorAuthenticationToken(byte[] data, DERValue[] values)
            : base(data, values, KerberosMessageType.KRB_ERROR)
        {
            ClientRealm = string.Empty;
            ClientName = new KerberosPrincipalName();
            ClientTime = null;
            ServerRealm = string.Empty;
            ServerName = new KerberosPrincipalName();
            ServerTime = null;
            ErrorText = string.Empty;
            ErrorData = new byte[0];
            ErrorDataList = new List<KerberosErrorData>().AsReadOnly();
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
            if (ClientTime != null)
            {
                builder.AppendLine($"Client Time       : {ClientTime.ToDateTime(ClientUSec)}");
            }
            if (!string.IsNullOrEmpty(ClientRealm))
            {
                builder.AppendLine($"Client Realm       : {ClientRealm}");
                builder.AppendLine($"Client Name        : {ClientName}");
            }

            builder.AppendLine($"Server Time       : {ServerTime.ToDateTime(ServerUSec)}");
            builder.AppendLine($"Server Realm      : {ServerRealm}");
            builder.AppendLine($"Server Name       : {ServerName}");
            builder.AppendLine($"Error Code        : {ErrorCode}");
            if (!string.IsNullOrEmpty(ErrorText))
                builder.AppendLine($"Error Text        : {ErrorText}");
            if (ErrorData.Length > 0)
            {
                builder.AppendLine($"Error Data        :");
                if (ErrorDataList.Count > 0)
                {
                    foreach (var data in ErrorDataList)
                    {
                        builder.AppendLine(data.ToString());
                    }
                }
                else
                {
                    HexDumpBuilder hex = new HexDumpBuilder();
                    hex.Append(ErrorData);
                    hex.Complete();
                    builder.Append(hex);
                }
            }

            return builder.ToString();
        }
        #endregion

        #region Public Static Members

        /// <summary>
        /// Create a new KRB-ERROR authentication token.
        /// </summary>
        /// <param name="client_time">Optional client time.</param>
        /// <param name="client_usec">Optional client time usecs.</param>
        /// <param name="server_time">Server time.</param>
        /// <param name="server_usec">Server time usecs.</param>
        /// <param name="error_code">Error code.</param>
        /// <param name="client_realm">Optional client realm.</param>
        /// <param name="client_name">Optional client name.</param>
        /// <param name="server_realm">Server realm</param>
        /// <param name="server_name">Server name.</param>
        /// <param name="error_text">Optional error text.</param>
        /// <param name="error_data">Optional error data.</param>
        /// <returns>The KRB-ERROR authentication token.</returns>
        public static KerberosErrorAuthenticationToken Create(KerberosTime server_time, int server_usec, KerberosErrorType error_code,
            string server_realm, KerberosPrincipalName server_name, KerberosTime client_time = null, int? client_usec = null, string client_realm = null,
            KerberosPrincipalName client_name = null,string error_text = null, byte[] error_data = null)
        {
            if (server_realm is null)
            {
                throw new ArgumentNullException(nameof(server_realm));
            }

            if (server_name is null)
            {
                throw new ArgumentNullException(nameof(server_name));
            }

            DERBuilder builder = new DERBuilder();
            using (var app = builder.CreateApplication(30))
            {
                using (var seq = app.CreateSequence())
                {
                    seq.WriteKerberosHeader(KerberosMessageType.KRB_ERROR);
                    seq.WriteContextSpecific(2, client_time);
                    seq.WriteContextSpecific(3, client_usec);
                    seq.WriteContextSpecific(4, server_time);
                    seq.WriteContextSpecific(5, server_usec);
                    seq.WriteContextSpecific(6, (int)error_code);
                    seq.WriteContextSpecific(7, client_realm);
                    seq.WriteContextSpecific(8, client_name);
                    seq.WriteContextSpecific(9, server_realm);
                    seq.WriteContextSpecific(10, server_name);
                    seq.WriteContextSpecific(11, error_text);
                    seq.WriteContextSpecific(12, error_data);
                }
            }
            return (KerberosErrorAuthenticationToken)Parse(builder.CreateGssApiWrapper(OIDValues.KERBEROS, 0x300));
        }

        /// <summary>
        /// Try and parse data into an Kerberos error authentication token.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <param name="token">The error authentication token.</param>
        /// <returns>True if successfully parsed.</returns>
        public static bool TryParse(byte[] data,  out KerberosErrorAuthenticationToken token)
        {
            token = null;
            if (!TryParse(data, null, out KerberosAuthenticationToken tmp_token))
            {
                return false;
            }

            token = (KerberosErrorAuthenticationToken)tmp_token;
            return true;
        }
        #endregion

        #region Internal Static Methods
        internal static bool TryParse(byte[] data, DERValue[] values, out KerberosAuthenticationToken token)
        {
            token = null;
            try
            {
                if (values == null)
                    values = DERParser.ParseData(data, 0);
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
                            ret.ClientTime = next.ReadChildKerberosTime();
                            break;
                        case 3:
                            ret.ClientUSec = next.ReadChildInteger();
                            break;
                        case 4:
                            ret.ServerTime = next.ReadChildKerberosTime();
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

                if (ret.ErrorData.Length > 0 && ret.ErrorCode != KerberosErrorType.PREAUTH_REQUIRED)
                {
                    ret.ErrorDataList = KerberosErrorData.Parse(ret.ErrorData).AsReadOnly();
                }

                token = ret;
                return true;
            }
            catch (InvalidDataException)
            {
                return false;
            }
            catch (EndOfStreamException)
            {
                return false;
            }
        }
        #endregion
    }
}
