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
using System.IO;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Authentication Token for Kerberos.
    /// </summary>
    public class KerberosAuthenticationToken : ASN1AuthenticationToken
    {
        #region Private Members
        private protected KerberosAuthenticationToken(byte[] data, DERValue[] values)
            : base(data, values)
        {
        }
        #endregion

        #region Internal Static Methods
        /// <summary>
        /// Try and parse data into an Kerberos authentication token.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <param name="token">The Kerberos authentication token.</param>
        /// <param name="client">True if this is a token from a client.</param>
        /// <param name="token_count">The token count number.</param>
        /// <returns>True if parsed successfully.</returns>
        internal static bool TryParse(byte[] data, int token_count, bool client, out KerberosAuthenticationToken token)
        {
            token = null;
            try
            {
                var values = DERParser.ParseData(data);
                if (values.Length != 1)
                    return false;
                var root = values[0];
                if (!root.CheckApplication(0))
                    return false;
                if (!root.HasChildren())
                    return false;
                if (!root.Children[0].CheckPrimitive(UniversalTag.OBJECT_IDENTIFIER))
                    return false;
                switch (root.Children[0].ReadObjID())
                {
                    case OIDValues.KERBEROS_OID:
                    case OIDValues.KERBEROS_USER_TO_USER_OID:
                        break;
                    default:
                        return false;
                }
                // TODO: Need to select out the different types of authentication tokens.
                token = new KerberosAuthenticationToken(data, values);
                return true;
            }
            catch (EndOfStreamException)
            {
                return false;
            }
        }
        #endregion
    }
}
