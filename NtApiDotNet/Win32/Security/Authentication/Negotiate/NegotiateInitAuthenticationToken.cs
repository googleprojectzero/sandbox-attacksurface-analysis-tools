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
using System;
using System.Collections.Generic;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Negotiate
{
    /// <summary>
    /// Flags for negotiation context.
    /// </summary>
    [Flags]
    public enum NegotiateContextFlags
    {
#pragma warning disable CS1591
        None = 0,
        Delegate = 1,
        Mutual = 2,
        Replay = 4,
        Sequence = 8,
        Anonymous = 0x10,
        Confidentiality = 0x20,
        Integrity = 0x40,
#pragma warning restore CS1591
    }

    /// <summary>
    /// Class to represent the negTokenInit message in SPNEGO.
    /// </summary>
    public sealed class NegotiateInitAuthenticationToken : NegotiateAuthenticationToken
    {
        /// <summary>
        /// List of supported negotiation mechanisms.
        /// </summary>
        public IEnumerable<string> MechanismList { get; }

        /// <summary>
        /// Context flags.
        /// </summary>
        public NegotiateContextFlags ContextFlags { get; }

        private protected override void FormatData(StringBuilder builder)
        {
            builder.AppendLine("Mechanism List     :");
            foreach (var oid in MechanismList)
            {
                builder.AppendLine($"{oid,-30} - {OIDValues.ToString(oid)}");
            }
            if (ContextFlags != NegotiateContextFlags.None)
            {
                builder.AppendLine($"Context Flags   : {ContextFlags}");
            }
        }

        internal NegotiateInitAuthenticationToken(byte[] data, IEnumerable<string> mechlist, 
            NegotiateContextFlags flags, AuthenticationToken token, byte[] mic)
            : base(data, token, mic)
        {
            MechanismList = mechlist;
            ContextFlags = flags;
        }
    }
}
