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
using NtApiDotNet.Utilities.ASN1.Parser;
using System;
using System.Collections.Generic;
using System.Linq;

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

        /// <summary>
        /// Convert to a list of ASN.1 objects.
        /// </summary>
        /// <returns>The list of ASN.1 objects.</returns>
        public IReadOnlyList<ASN1Object> ToASN1Object()
        {
            return _values.Select(ASN1Object.ToObject).ToList().AsReadOnly();
        }

        #region Internal Static Methods
        internal static bool TryParse(byte[] data, int token_count, bool client, out ASN1AuthenticationToken token)
        {
            token = null;
            try
            {
                token = new ASN1AuthenticationToken(data);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }
        #endregion
    }
}
