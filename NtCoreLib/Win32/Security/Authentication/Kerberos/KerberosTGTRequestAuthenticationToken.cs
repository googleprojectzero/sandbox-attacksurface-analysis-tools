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
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent a User to User TGT Request.
    /// </summary>
    public sealed class KerberosTGTRequestAuthenticationToken : KerberosAuthenticationToken
    {
        #region Public Properties
        /// <summary>
        /// Realm.
        /// </summary>
        public string Realm { get; private set; }
        /// <summary>
        /// Server name.
        /// </summary>
        public KerberosPrincipalName ServerName { get; private set; }
        #endregion

        #region Private Members
        private KerberosTGTRequestAuthenticationToken(byte[] data, DERValue[] values)
            : base(data, values, KerberosMessageType.KRB_TGT_REQ)
        {
            Realm = string.Empty;
            ServerName = new KerberosPrincipalName();
        }

        private static DERBuilder CreateBuilder(string realm, KerberosPrincipalName server_name)
        {
            DERBuilder builder = new DERBuilder();
            using (var seq = builder.CreateSequence())
            {
                seq.WriteKerberosHeader(KerberosMessageType.KRB_TGT_REQ);
                seq.WriteContextSpecific(2, server_name);
                seq.WriteContextSpecific(3, realm);
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
            if (ServerName.NameType == KerberosNameType.PRINCIPAL)
            {
                builder.AppendLine($"Principal: {ServerName.GetPrincipal(Realm)}");
            }
            else
            {
                builder.AppendLine($"ServerName : {ServerName}");
                builder.AppendLine($"Realm      : {Realm}");
            }
            return builder.ToString();
        }
        #endregion

        #region Public Static Members
        /// <summary>
        /// Create a new TGT-REQ authentication token.
        /// </summary>
        /// <param name="realm">Optional realm string.</param>
        /// <param name="server_name">Optional server name.</param>
        /// <returns>The new TGT-REQ authentication token.</returns>
        public static KerberosTGTRequestAuthenticationToken Create(string realm, KerberosPrincipalName server_name)
        {
            return (KerberosTGTRequestAuthenticationToken)Parse(CreateBuilder(realm, 
                server_name).CreateGssApiWrapper(OIDValues.KERBEROS_USER_TO_USER, 0x400));
        }

        /// <summary>
        /// Create a new TGT-REQ authentication token without the GSS-API wrapper.
        /// </summary>
        /// <param name="realm">Optional realm string.</param>
        /// <param name="server_name">Optional server name.</param>
        /// <returns>The new TGT-REQ authentication token.</returns>
        public static KerberosTGTRequestAuthenticationToken CreateNoGSSAPI(string realm, KerberosPrincipalName server_name)
        {
            return (KerberosTGTRequestAuthenticationToken)Parse(CreateBuilder(realm, server_name).ToArray());
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
                var ret = new KerberosTGTRequestAuthenticationToken(data, values);

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
                            if ((KerberosMessageType)next.ReadChildInteger() != KerberosMessageType.KRB_TGT_REQ)
                                return false;
                            break;
                        case 2:
                            if (!next.Children[0].CheckSequence())
                            {
                                return false;
                            }
                            ret.ServerName = KerberosPrincipalName.Parse(next.Children[0]);
                            break;
                        case 3:
                            ret.Realm = next.ReadChildGeneralString();
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
