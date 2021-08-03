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

using NtApiDotNet.Utilities.Memory;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Class to represent a IPsec identity 
    /// </summary>
    public sealed class IPsecIdentity
    {
        /// <summary>
        /// Main-mode target name.
        /// </summary>
        public string MmTargetName { get; }
        /// <summary>
        /// Extended mode target name.
        /// </summary>
        public string EmTargetName { get; }
        /// <summary>
        /// List of tokens.
        /// </summary>
        public IReadOnlyList<IPsecToken> Tokens { get; }
        /// <summary>
        /// Explicit credentials handle.
        /// </summary>
        public ulong ExplicitCredentials { get; }
        /// <summary>
        /// Logon ID.
        /// </summary>
        public ulong LogonId { get; }

        internal IPsecIdentity(IPSEC_ID0 id)
        {
            MmTargetName = id.mmTargetName ?? string.Empty;
            EmTargetName = id.emTargetName ?? string.Empty;
            List<IPsecToken> tokens = new List<IPsecToken>();
            if (id.numTokens > 0 && id.tokens != IntPtr.Zero)
            {
                tokens.AddRange(id.tokens.ReadArray<IPSEC_TOKEN0>(id.numTokens).Select(t => new IPsecToken(t)));
            }
            Tokens = tokens.AsReadOnly();
            ExplicitCredentials = id.explicitCredentials;
            LogonId = id.logonId;
        }
    }
}
