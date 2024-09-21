//  Copyright 2021 Google LLC. All Rights Reserved.
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

using NtApiDotNet.Win32;
using System;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Class to represent an IPsec token.
    /// </summary>
    public sealed class IPsecToken
    {
        /// <summary>
        /// Type of token.
        /// </summary>
        public IPSEC_TOKEN_TYPE Type { get; }

        /// <summary>
        /// Token principal.
        /// </summary>
        public IPSEC_TOKEN_PRINCIPAL Principal { get; }

        /// <summary>
        /// Token mode.
        /// </summary>
        public IPSEC_TOKEN_MODE Mode { get; }

        /// <summary>
        /// Handle to the token.
        /// </summary>
        public long Token { get; }

        /// <summary>
        /// Get the token from the IKEEXT service.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The token.</returns>
        public NtResult<NtToken> GetToken(bool throw_on_error)
        {
            int pid = ServiceUtils.GetService("IKEEXT", false).GetResultOrDefault()?.ProcessId ?? 0;
            return NtToken.DuplicateFrom(pid, new IntPtr(Token), 
                TokenAccessRights.None, DuplicateObjectOptions.SameAccess, throw_on_error);
        }

        /// <summary>
        /// Get the token from the IKEEXT service.
        /// </summary>
        /// <returns>The token.</returns>
        public NtToken GetToken()
        {
            return GetToken(true).Result;
        }

        internal IPsecToken(IPSEC_TOKEN0 token)
        {
            Type = token.type;
            Principal = token.principal;
            Mode = token.mode;
            Token = token.token;
        }
    }
}
