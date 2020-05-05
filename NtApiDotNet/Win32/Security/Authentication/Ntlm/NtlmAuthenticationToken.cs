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

using NtApiDotNet.Utilities.Text;
using System;
using System.IO;

namespace NtApiDotNet.Win32.Security.Authentication.Ntlm
{
#pragma warning disable 1591
    /// <summary>
    /// Flags for NTLM negotiation.
    /// </summary>
    [Flags]
    public enum NtlmNegotiateFlags : uint
    {
        Key56Bit = (1U << 31),
        KeyExchange = (1 << 30),
        Key128Bit = (1 << 29),
        UnusedR1 = (1 << 28),
        UnusedR2 = (1 << 27),
        UnusedR3 = (1 << 26),
        Version = (1 << 25),
        UnusedR4 = (1 << 24),
        TargetInfo = (1 << 23),
        RequestNonNTSessionKey = (1 << 22),
        Accept = (1 << 21),
        Identity = (1 << 20),
        ExtendedSessionSecurity = (1 << 19),
        TargetTypeShare = (1 << 18),
        TargetTypeServer = (1 << 17),
        TargetTypeDomain = (1 << 16),
        AlwaysSign = (1 << 15),
        LocalCall = (1 << 14),
        OemWorkstationSupplied = (1 << 13),
        OemDomainSupplied = (1 << 12),
        Anonymous = (1 << 11),
        UnusedR8 = (1 << 10),
        NTLM = (1 << 9),
        UnusedR9 = (1 << 8),
        LMKey = (1 << 7),
        Datagram = (1 << 6),
        Seal = (1 << 5),
        Signing = (1 << 4),
        UnusedR10 = (1 << 3),
        RequestTarget = (1 << 2),
        Oem = (1 << 1),
        Unicode = (1 << 0),
    }

    /// <summary>
    /// NTLM message type.
    /// </summary>
    public enum NtlmMessageType
    {
        None = 0,
        Negotiate = 1,
        Challenge = 2,
        Authenticate = 3,
    }

#pragma warning restore

    /// <summary>
    /// Base class to represent an NTLM authentication token.
    /// </summary>
    public abstract class NtlmAuthenticationToken : AuthenticationToken
    {
        #region Private Members
        private const string NTLM_MAGIC = "NTLMSSP\0";

        private protected NtlmAuthenticationToken(
            byte[] data, NtlmMessageType message_type, 
            NtlmNegotiateFlags flags) : base(data)
        {
            MessageType = message_type;
            Flags = flags;
        }

        #endregion

        #region Public Properties
        /// <summary>
        /// Type of NTLM message.
        /// </summary>
        public NtlmMessageType MessageType { get; }

        /// <summary>
        /// NTLM negotitation flags.
        /// </summary>
        public NtlmNegotiateFlags Flags { get; }
        #endregion

        #region Internal Static Methods
        /// <summary>
        /// Try and parse data into an NTLM authentication token.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <param name="token">The NTLM authentication token.</param>
        /// <param name="client">True if this is a token from a client.</param>
        /// <param name="token_count">The token count number.</param>
        /// <returns>True if parsed successfully.</returns>
        internal static bool TryParse(byte[] data, int token_count, bool client, out NtlmAuthenticationToken token)
        {
            token = null;
            if (data.Length < 12)
                return false;
            if (BinaryEncoding.Instance.GetString(data, 0, 8) != NTLM_MAGIC)
                return false;
            MemoryStream stm = new MemoryStream(data);
            BinaryReader reader = new BinaryReader(stm);
            stm.Position = 8;
            NtlmMessageType type = (NtlmMessageType)reader.ReadInt32();
            switch (type)
            {
                case NtlmMessageType.Negotiate:
                    return NtlmNegotiateAuthenticationToken.TryParse(data, reader, out token);
                case NtlmMessageType.Challenge:
                    return NtlmChallengeAuthenticationToken.TryParse(data, reader, out token);
                case NtlmMessageType.Authenticate:
                    return NtlmAuthenticateAuthenticationToken.TryParse(data, reader, out token);
                default:
                    return false;
            }
        }
        #endregion

        #region Public Static Methods
        /// <summary>
        /// Try and parse data into an NTLM authentication token.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <returns>The NTLM authentication token.</returns>
        public static NtlmAuthenticationToken Parse(byte[] data)
        {
            if (!TryParse(data, 0, false, out NtlmAuthenticationToken token))
                throw new ArgumentException(nameof(data));
            return token;
        }
        #endregion
    }
}
