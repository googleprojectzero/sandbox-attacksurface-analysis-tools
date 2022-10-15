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
using NtApiDotNet.Win32.Security.Authentication.Kerberos.PkInit;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.PKU2U
{
    /// <summary>
    /// Class to represent a PKU2U metadata token.
    /// </summary>
    public sealed class PKU2UMetaDataAuthenticationToken : ASN1AuthenticationToken
    {
        /// <summary>
        /// List of trusted certifiers.
        /// </summary>
        public IReadOnlyList<KerberosPkInitExternalPrincipalIdentifier> TrustedCertifiers { get; }

        /// <summary>
        /// Expected server name.
        /// </summary>
        public KerberosPkInitPrincipalName ServerName { get; }

        /// <summary>
        /// Format the token to a string.
        /// </summary>
        /// <returns>The token as a string.</returns>
        public override string Format()
        {
            StringBuilder builder = new StringBuilder();
            if (TrustedCertifiers.Count > 0)
            {
                var names = string.Join(", ", TrustedCertifiers.Select(c => c.SubjectName.Name));
                builder.AppendLine($"Trusted Certifiers: {names}");
            }
            if (ServerName != null)
            {
                builder.AppendLine($"Server Realm      : {ServerName.Realm}");
                builder.AppendLine($"Server Name       : {ServerName.PrincipalName}");
            }
            return builder.ToString();
        }

        internal PKU2UMetaDataAuthenticationToken(byte[] data, DERValue[] values, 
            List<KerberosPkInitExternalPrincipalIdentifier> trusted_certifiers, KerberosPkInitPrincipalName server_name) 
            : base(data, values)
        {
            TrustedCertifiers = trusted_certifiers?.AsReadOnly();
            ServerName = server_name;
        }

        #region Internal Methods
        internal static bool TryParse(byte[] data, int token_count, bool client, out PKU2UMetaDataAuthenticationToken token)
        {
            token = null;
            try
            {
                var values = DERParser.ParseData(data);
                if (values.Length != 1 || !values[0].CheckSequence() || !values[0].HasChildren())
                    return false;

                List<KerberosPkInitExternalPrincipalIdentifier> trusted_certifiers = null;
                KerberosPkInitPrincipalName server_name = null;
                foreach (var next in values[0].Children)
                {
                    if (next.Type != DERTagType.ContextSpecific)
                        return false;
                    switch (next.Tag)
                    {
                        case 0:
                            trusted_certifiers = next.ReadChildSequence(v => KerberosPkInitExternalPrincipalIdentifier.Parse(v));
                            break;
                        case 1:
                            server_name = KerberosPkInitPrincipalName.Parse(next.Children);
                            break;
                        default:
                            return false;
                    }
                }
                token = new PKU2UMetaDataAuthenticationToken(data, values, trusted_certifiers, server_name);
                return true;
            }
            catch
            {
                return false;
            }
        }
        #endregion
    }
}
