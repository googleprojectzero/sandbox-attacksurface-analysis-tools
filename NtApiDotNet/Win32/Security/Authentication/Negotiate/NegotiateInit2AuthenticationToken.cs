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
using NtApiDotNet.Utilities.ASN1.Builder;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Negotiate
{
    /// <summary>
    /// Class to represent a NegTokenInit2 token.
    /// </summary>
    public sealed class NegotiateInit2AuthenticationToken : NegotiateInitAuthenticationToken
    {
        internal NegotiateInit2AuthenticationToken(byte[] data, IEnumerable<string> mechlist, 
            NegotiateContextFlags flags, AuthenticationToken token, byte[] mic, string hint_name, byte[] hint_address) 
            : base(data, mechlist, flags, token, mic)
        {
            HintName = hint_name;
            HintAddress = hint_address;
        }

        /// <summary>
        /// Hint name.
        /// </summary>
        public string HintName { get; }

        /// <summary>
        /// Hint address.
        /// </summary>
        public byte[] HintAddress { get; }

        private protected override void FormatData(StringBuilder builder)
        {
            base.FormatData(builder);
            if (HintName != null)
            {
                builder.AppendLine($"Hint Name       : {HintName}");
            }
            if (HintAddress != null)
            {
                builder.AppendLine($"Hint Addresss   : {NtObjectUtils.ToHexString(HintAddress)}");
            }
        }

        /// <summary>
        /// Create a NegTokenInit token.
        /// </summary>
        /// <param name="mech_types">The list of authentication mechanisms we support.</param>
        /// <param name="hint_name">Hint name.</param>
        /// <param name="hint_address">Hint address.</param>
        /// <param name="flags">Optional flags.</param>
        /// <param name="mech_token">An initial authentication token.</param>
        /// <param name="mech_list_mic">Optional mechanism list MIC.</param>
        /// <param name="wrap_gssapi">Specify to wrap the token is a GSS-API wrapper.</param>
        /// <returns>The init token.</returns>
        public static NegotiateInit2AuthenticationToken Create(IEnumerable<string> mech_types, string hint_name,
            byte[] hint_address = null, NegotiateContextFlags? flags = null, AuthenticationToken mech_token = null, byte[] mech_list_mic = null,
            bool wrap_gssapi = true)
        {
            if (mech_types is null)
            {
                throw new ArgumentNullException(nameof(mech_types));
            }

            if (hint_name is null)
            {
                throw new ArgumentNullException(nameof(hint_name));
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
                    using (var neg_hints_ctx = seq.CreateContextSpecific(3))
                    {
                        using (var neg_hints = neg_hints_ctx.CreateSequence())
                        {
                            neg_hints.WriteContextSpecific(0, hint_name);
                            neg_hints.WriteContextSpecific(1, hint_address);
                        }
                    }
                    seq.WriteContextSpecific(4, mech_list_mic);
                }
            }
            byte[] token = wrap_gssapi ? GSSAPIUtils.Wrap(OIDValues.SPNEGO, builder.ToArray()) : builder.ToArray();
            return (NegotiateInit2AuthenticationToken)Parse(token);
        }
    }
}
