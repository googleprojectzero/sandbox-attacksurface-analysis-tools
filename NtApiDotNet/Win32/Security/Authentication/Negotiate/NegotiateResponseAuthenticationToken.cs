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
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Negotiate
{
    /// <summary>
    /// State of the Negotiate state.
    /// </summary>
    public enum NegotiateAuthenticationState
    {
        /// <summary>
        /// Negotiate completed.
        /// </summary>
        Completed = 0,
        /// <summary>
        /// Negotiate incomplete.
        /// </summary>
        Incomplete = 1,
        /// <summary>
        /// Negotiate rejected.
        /// </summary>
        Reject = 2,
        /// <summary>
        /// Request Message Integrity Code.
        /// </summary>
        RequestMIC = 3
    }

    /// <summary>
    /// Class to represent the negTokenResp message in SPNEGO.
    /// </summary>
    public sealed class NegotiateResponseAuthenticationToken : NegotiateAuthenticationToken
    {
        /// <summary>
        /// Supported mechanism for the token, optional.
        /// </summary>
        public string SupportedMechanism { get; }

        /// <summary>
        /// Current state of the negotiation.
        /// </summary>
        public NegotiateAuthenticationState State { get; }

        private protected override void FormatData(StringBuilder builder)
        {
            if (!string.IsNullOrWhiteSpace(SupportedMechanism))
            {
                builder.AppendLine($"Supported Mech    : {SupportedMechanism} - {OIDValues.ToString(SupportedMechanism)}");
            }
            builder.AppendLine($"State             : {State}");
        }

        internal NegotiateResponseAuthenticationToken(byte[] data, 
            string supported_mech, NegotiateAuthenticationState state, AuthenticationToken token, byte[] mic)
            : base(data, token, mic)
        {
            SupportedMechanism = supported_mech;
            State = state;
        }
    }
}
