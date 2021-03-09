//  Copyright 2021 Google Inc. All Rights Reserved.
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

using System;
using System.Collections.Generic;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Digest
{
    /// <summary>
    /// Authentication token for a digest token.
    /// </summary>
    public sealed class DigestAuthenticationToken : AuthenticationToken
    {
        private readonly Lazy<List<string>> _split_token;

        /// <summary>
        /// The digest token as a string.
        /// </summary>
        public string Data { get; }

        /// <summary>
        /// Format the authentication token.
        /// </summary>
        /// <returns></returns>
        public override string Format()
        {
            return string.Join("," + Environment.NewLine, _split_token.Value);
        }

        private DigestAuthenticationToken(byte[] data) : base(data)
        {
            Data = Encoding.UTF8.GetString(data);
            _split_token = new Lazy<List<string>>(SplitToken);
        }

        private List<string> SplitToken()
        {
            int start_index = 0;
            bool in_quote = false;
            List<string> ret = new List<string>();

            for (int i = 0; i < Data.Length - 1; ++i)
            {
                if (Data[i] == ',' && !in_quote)
                {
                    ret.Add(Data.Substring(start_index, i - start_index));
                    start_index = i + 1;
                }
                else if (Data[i] == '"')
                {
                    in_quote = !in_quote;
                }
            }
            ret.Add(Data.Substring(start_index));
            return ret;
        }

        internal static bool TryParse(byte[] data, out DigestAuthenticationToken token)
        {
            token = null;
            try
            {
                token = new DigestAuthenticationToken(data);
                return true;
            }
            catch (ArgumentException)
            {
                return false;
            }
        }
    }
}
