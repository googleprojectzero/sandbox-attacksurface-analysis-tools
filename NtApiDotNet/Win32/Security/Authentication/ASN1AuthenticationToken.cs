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

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Authentication token constructed from ASN1.
    /// </summary>
    public class ASN1AuthenticationToken : AuthenticationToken
    {
        private protected readonly DERValue[] _values;

        private protected ASN1AuthenticationToken(byte[] data, DERValue[] values)
            : base(data)
        {
            _values = values;
        }

        private protected ASN1AuthenticationToken(byte[] data)
            : this(data, DERParser.ParseData(data, 0))
        {
        }

        /// <summary>
        /// Format the Authentication Token.
        /// </summary>
        /// <returns>The Formatted Token.</returns>
        public override string Format()
        {
            return ASN1Utils.FormatDER(_values, 0);
        }

        #region Internal Static Methods
        /// <summary>
        /// Try and parse data into an ASN1 authentication token.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <param name="token">The Negotiate authentication token.</param>
        /// <param name="client">True if this is a token from a client.</param>
        /// <param name="token_count">The token count number.</param>
        /// <returns>True if parsed successfully.</returns>
        internal static bool TryParse(byte[] data, int token_count, bool client, out ASN1AuthenticationToken token)
        {
            token = null;
            try
            {
                token = new ASN1AuthenticationToken(data);
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
