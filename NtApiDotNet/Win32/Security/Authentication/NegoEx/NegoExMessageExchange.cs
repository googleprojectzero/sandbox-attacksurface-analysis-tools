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

using NtApiDotNet.Utilities.Data;
using NtApiDotNet.Win32.Security.Authentication.Kerberos;
using NtApiDotNet.Win32.Security.Authentication.PKU2U;
using System;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.NegoEx
{
    /// <summary>
    /// Class for a NEGOEX EXCHANGE_MESSAGE message.
    /// </summary>
    public sealed class NegoExMessageExchange : NegoExMessage
    {
        /// <summary>
        /// The authentication scheme selected.
        /// </summary>
        public Guid AuthScheme { get; }

        /// <summary>
        /// The exchanged authentication token.
        /// </summary>
        public AuthenticationToken Exchange { get; }

        private NegoExMessageExchange(NegoExMessageHeader header, Guid auth_scheme, AuthenticationToken exchange) : base(header)
        {
            AuthScheme = auth_scheme;
            Exchange = exchange;
        }

        internal static NegoExMessageExchange Parse(NegoExMessageHeader header, byte[] data)
        {
            DataReader reader = new DataReader(data);
            reader.Position = NegoExMessageHeader.HEADER_SIZE;
            Guid auth_scheme = reader.ReadGuid();
            byte[] exchange = ReadByteVector(reader, data);
            AuthenticationToken token = null;
            if (auth_scheme == NegoExAuthSchemes.PKU2U)
            {
                if (header.MessageType == NegoExMessageType.AcceptorMetaData || header.MessageType == NegoExMessageType.InitiatorMetaData)
                {
                    if (PKU2UMetaDataAuthenticationToken.TryParse(exchange, 0, false, out PKU2UMetaDataAuthenticationToken pku2u_token))
                    {
                        token = pku2u_token;
                    }
                }
                else if (KerberosAuthenticationToken.TryParse(exchange, 0, false, out KerberosAuthenticationToken kerb_token))
                {
                    token = kerb_token;
                }
            }

            return new NegoExMessageExchange(header, auth_scheme, token ?? new AuthenticationToken(exchange));
        }

        private protected override void InnerFormat(StringBuilder builder)
        {
            builder.AppendLine($"Auth Scheme      : {FormatAuthScheme(AuthScheme)}");
            builder.AppendLine("Exchange         :");
            builder.AppendLine(Exchange.Format().TrimEnd());
        }
    }
}
