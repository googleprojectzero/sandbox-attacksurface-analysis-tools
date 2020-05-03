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
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Ntlm
{
    /// <summary>
    /// Class to represent an NTLM AUTHENTICATE token for NTLMv2.
    /// </summary>
    public class NtlmAuthenticateAuthenticationTokenV2 : NtlmAuthenticateAuthenticationToken
    {
        /// <summary>
        /// NT Proof Response.
        /// </summary>
        public byte[] NTProofResponse { get; }
        /// <summary>
        /// Challenge version.
        /// </summary>
        public byte ChallengeVersion { get; private set; }
        /// <summary>
        /// Maximum challenge version.
        /// </summary>
        public byte MaxChallengeVersion { get; }
        /// <summary>
        /// Reserved field.
        /// </summary>
        public ushort Reserved1 { get; }
        /// <summary>
        /// Reserved field.
        /// </summary>
        public uint Reserved2 { get; }
        /// <summary>
        /// Timestamp.
        /// </summary>
        public long Timestamp { get; }
        /// <summary>
        /// Client challenge.
        /// </summary>
        public byte[] ClientChallenge { get; }
        /// <summary>
        /// Reserved field.
        /// </summary>
        public uint Reserved3 { get; }
        /// <summary>
        /// NTLM Target Information.
        /// </summary>
        public IReadOnlyList<NtlmAvPair> TargetInfo { get; }

        #region Constructors
        private protected NtlmAuthenticateAuthenticationTokenV2(byte[] data,
            NtlmNegotiateFlags flags, string domain, string username,
            string workstation, byte[] lmresponse, byte[] ntresponse,
            byte[] session_key, byte[] mic, int mic_offset, Version version,
            byte[] nt_proof, byte challenge_ver, byte max_challenge_ver,
            ushort reserved_1, uint reserved_2, long timestamp,
            byte[] client_challenge, uint reserved_3, List<NtlmAvPair> target_info)
            : base(data,flags, domain, username, workstation,
                  lmresponse, ntresponse, session_key, mic, mic_offset, version)
        {
            NTProofResponse = nt_proof;
            ChallengeVersion = challenge_ver;
            MaxChallengeVersion = max_challenge_ver;
            Reserved1 = reserved_1;
            Reserved2 = reserved_2;
            Reserved3 = reserved_3;
            Timestamp = timestamp;
            ClientChallenge = client_challenge;
            TargetInfo = target_info.AsReadOnly();
        }
        #endregion

        #region Private Members

        private protected override void FormatNTResponse(StringBuilder builder)
        {
            builder.AppendLine("<NTLMv2 Challenge Response>");
            builder.AppendLine($"NT Response          : {NtObjectUtils.ToHexString(NTProofResponse)}");
            builder.AppendLine($"Challenge Verison    : {ChallengeVersion}");
            builder.AppendLine($"Max Challenge Verison: {MaxChallengeVersion}");
            builder.AppendLine($"Reserved 1           : 0x{Reserved1:X04}");
            builder.AppendLine($"Reserved 2           : 0x{Reserved2:X08}");
            try
            {
                builder.AppendLine($"Timestamp            : {DateTime.FromFileTime(Timestamp)}");
            }
            catch (ArgumentOutOfRangeException)
            {
                builder.AppendLine($"Timestamp            : 0x{Timestamp:X016}");
            }
            builder.AppendLine($"Client Challenge     : {NtObjectUtils.ToHexString(ClientChallenge)}");
            builder.AppendLine($"Reserved 3           : 0x{Reserved3:X08}");
            foreach (var pair in TargetInfo)
            {
                builder.AppendLine(pair.ToString());
            }
            builder.AppendLine("</NTLMv2 Challenge Response>");
        }
        #endregion

        #region Internal Methods
        internal static bool TryParse(byte[] data, 
            NtlmNegotiateFlags flags, string domain, string username,
            string workstation, byte[] lm_response, byte[] nt_response,
            byte[] session_key, byte[] mic, int mic_offset, Version version, 
            out NtlmAuthenticationToken token)
        {
            token = null;
            if (nt_response?.Length < 44)
                return false;

            try
            {
                BinaryReader reader = new BinaryReader(new MemoryStream(nt_response));
                byte[] nt_proof = reader.ReadBytes(16);
                byte challenge_ver = reader.ReadByte();
                byte max_challenge_ver = reader.ReadByte();
                ushort reserved_1 = reader.ReadUInt16();
                uint reserved_2 = reader.ReadUInt32();
                long timestamp = reader.ReadInt64();
                byte[] client_challenge = reader.ReadBytes(8);
                uint reserved_3 = reader.ReadUInt32();

                if (!NtlmUtils.TryParseAvPairs(reader, out List<NtlmAvPair> av_pairs))
                {
                    return false;
                }

                token = new NtlmAuthenticateAuthenticationTokenV2(data, flags, domain, username, workstation, lm_response, nt_response,
                    session_key, mic, mic_offset, version, nt_proof, challenge_ver, max_challenge_ver, reserved_1, reserved_2,
                    timestamp, client_challenge, reserved_3, av_pairs);
                return true;
            }
            catch (EndOfStreamException)
            {
                return false;
            }
}
        #endregion
    }
}
