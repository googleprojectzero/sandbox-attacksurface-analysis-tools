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
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Negotiate
{
    /// <summary>
    /// Flags for negotiation context.
    /// </summary>
    [Flags]
    public enum NegotiateContextFlags : uint
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
    public class NegotiateInitAuthenticationToken : NegotiateAuthenticationToken
    {
        /// <summary>
        /// List of supported negotiation mechanisms.
        /// </summary>
        public IEnumerable<string> MechanismList { get; }

        /// <summary>
        /// Context flags.
        /// </summary>
        public NegotiateContextFlags ContextFlags { get; }

        /// <summary>
        /// Create a NegTokenInit token.
        /// </summary>
        /// <param name="mech_types">The list of authentication mechanisms we support.</param>
        /// <param name="flags">Optional flags.</param>
        /// <param name="mech_token">An initial authentication token.</param>
        /// <param name="mech_list_mic">Optional mechanism list MIC.</param>
        /// <param name="wrap_gssapi">Specify to wrap the token is a GSS-API wrapper.</param>
        /// <returns>The init token.</returns>
        public static NegotiateInitAuthenticationToken Create(IEnumerable<string> mech_types,
            NegotiateContextFlags? flags = null, AuthenticationToken mech_token = null, byte[] mech_list_mic = null,
            bool wrap_gssapi = true)
        {
            if (mech_types is null)
            {
                throw new ArgumentNullException(nameof(mech_types));
            }

            DERBuilder builder = new DERBuilder();
            using (var context = builder.CreateContextSpecific(0))
            {
                using (var seq = context.CreateSequence())
                {
                    seq.WriteContextSpecific(0, mech_types.Select(t => new DERObjectIdentifier(t)));
                    if (flags.HasValue)
                    {
                        seq.WriteContextSpecific(1, b => b.WriteBitString(flags.Value));
                    }
                    seq.WriteContextSpecific(2, mech_token?.ToArray());
                    seq.WriteContextSpecific(3, mech_list_mic);
                }
            }
            byte[] token = wrap_gssapi ? GSSAPIUtils.Wrap(OIDValues.SPNEGO, builder.ToArray()) : builder.ToArray();
            return (NegotiateInitAuthenticationToken)Parse(token);
        }

        private protected override void FormatData(StringBuilder builder)
        {
            builder.AppendLine("Mechanism List  :");
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
