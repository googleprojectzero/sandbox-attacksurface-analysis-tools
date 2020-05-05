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

using System;
using System.IO;
using System.Linq;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Ntlm
{
    /// <summary>
    /// Class to represent an NTLM AUTHENTICATE token for NTLMv1.
    /// </summary>
    public class NtlmAuthenticateAuthenticationToken : NtlmAuthenticationToken
    {
        #region Public Properties
        /// <summary>
        /// Domain name.
        /// </summary>
        public string Domain { get; }
        /// <summary>
        /// Workstation name.
        /// </summary>
        public string Workstation { get; }
        /// <summary>
        /// Username.
        /// </summary>
        public string UserName { get; }
        /// <summary>
        /// NTLM version.
        /// </summary>
        public Version Version { get; }
        /// <summary>
        /// Encrypted session key.
        /// </summary>
        public byte[] EncryptedSessionKey { get; }
        /// <summary>
        /// LM Challenge Response.
        /// </summary>
        public byte[] LmChallengeResponse { get; }
        /// <summary>
        /// LM Challenge Response.
        /// </summary>
        public byte[] NtChallengeResponse { get; }
        /// <summary>
        /// Message integrity code.
        /// </summary>
        public byte[] MessageIntegrityCode { get; }
        /// <summary>
        /// Message integrity code offset into the token data.
        /// </summary>
        public int MessageIntegrityCodeOffset { get; }
        #endregion

        #region Constructors
        private protected NtlmAuthenticateAuthenticationToken(byte[] data, 
            NtlmNegotiateFlags flags, string domain, string username,
            string workstation, byte[] lmresponse, byte[] ntresponse,
            byte[] session_key, byte[] mic, int mic_offset, Version version)
            : base(data, NtlmMessageType.Negotiate, flags)
        {
            Domain = domain;
            Workstation = workstation;
            Version = version;
            UserName = username;
            LmChallengeResponse = lmresponse;
            NtChallengeResponse = ntresponse;
            EncryptedSessionKey = session_key;
            MessageIntegrityCode = mic;
            MessageIntegrityCodeOffset = mic_offset;
        }
        #endregion

        #region Private Members

        private protected virtual void FormatNTResponse(StringBuilder builder)
        {
            builder.AppendLine($"NT Response: {NtObjectUtils.ToHexString(NtChallengeResponse)}");
        }

        private static int MinimumPosition(params int[] ps)
        {
            return ps.Min();
        }

        #endregion

        #region Public Methods
        /// <summary>
        /// Format the authentication token.
        /// </summary>
        /// <returns>The formatted token.</returns>
        public override string Format()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine("<NTLM AUTHENTICATE>");
            builder.AppendLine($"Flags      : {Flags}");
            if (!string.IsNullOrEmpty(Domain))
            {
                builder.AppendLine($"Domain     : {Domain}");
            }
            if (!string.IsNullOrEmpty(UserName))
            {
                builder.AppendLine($"UserName   : {UserName}");
            }
            if (!string.IsNullOrEmpty(Workstation))
            {
                builder.AppendLine($"Workstation: {Workstation}");
            }
            builder.AppendLine($"LM Response: {NtObjectUtils.ToHexString(LmChallengeResponse)}");
            FormatNTResponse(builder);
            if (EncryptedSessionKey.Length > 0)
            {
                builder.AppendLine($"Session Key: {NtObjectUtils.ToHexString(EncryptedSessionKey)}");
            }

            if (Version != null)
            {
                builder.AppendLine($"Version    : {Version}");
            }

            if (MessageIntegrityCode.Length > 0)
            {
                builder.AppendLine($"MIC        : {NtObjectUtils.ToHexString(MessageIntegrityCode)}");
            }

            return builder.ToString();
        }
        #endregion

        #region Internal Methods
        internal static bool TryParse(byte[] data, BinaryReader reader, out NtlmAuthenticationToken token)
        {
            token = null;

            if (!NtlmUtils.TryParseStringValues(reader, out int lm_length, out int lm_position))
                return false;

            if (!NtlmUtils.TryParseStringValues(reader, out int nt_length, out int nt_position))
                return false;

            if (!NtlmUtils.TryParseStringValues(reader, out int domain_length, out int domain_position))
                return false;

            if (!NtlmUtils.TryParseStringValues(reader, out int username_length, out int username_position))
                return false;

            if (!NtlmUtils.TryParseStringValues(reader, out int workstation_length, out int workstation_position))
                return false;

            if (!NtlmUtils.TryParseStringValues(reader, out int key_length, out int key_position))
                return false;

            NtlmNegotiateFlags flags = (NtlmNegotiateFlags)reader.ReadInt32();
            if (!NtlmUtils.TryParse(reader, out Version version))
                return false;

            long min_pos = MinimumPosition(lm_position, nt_position, domain_position, username_position, workstation_position, key_position);
            byte[] mic = new byte[0];
            int mic_offset = int.MaxValue;
            if (reader.BaseStream.Position + 16 <= min_pos)
            {
                mic_offset = (int)reader.BaseStream.Position;
                mic = reader.ReadBytes(16);
                if (mic.Length < 16)
                    return false;
            }

            string domain = string.Empty;
            if (domain_position != 0)
            {
                if (!NtlmUtils.ParseString(flags, data, domain_length, domain_position, out domain))
                    return false;
            }

            string workstation = string.Empty;
            if (workstation_position != 0)
            {
                if (!NtlmUtils.ParseString(flags, data, workstation_length, workstation_position, out workstation))
                    return false;
            }

            string username = string.Empty;
            if (username_position != 0)
            {
                if (!NtlmUtils.ParseString(flags, data, username_length, username_position, out username))
                    return false;
            }

            if (!NtlmUtils.ParseBytes(data, lm_length, lm_position, out byte[] lm_response))
                return false;

            if (!NtlmUtils.ParseBytes(data, nt_length, nt_position, out byte[] nt_response))
                return false;

            if (!NtlmUtils.ParseBytes(data, key_length, key_position, out byte[] key))
                return false;

            if (!NtlmAuthenticateAuthenticationTokenV2.TryParse(data, flags, domain, username, workstation, lm_response, nt_response,
                            key, mic, mic_offset, version, out token))
            {
                token = new NtlmAuthenticateAuthenticationToken(data, flags, domain, username, workstation, lm_response, nt_response,
                key, mic, mic_offset, version);
            }

            return true;
        }
        #endregion
    }
}
