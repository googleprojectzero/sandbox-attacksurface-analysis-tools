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

using NtApiDotNet.Win32.Security.Authentication.Ntlm.Client;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace NtApiDotNet.Win32.Security.Authentication.Ntlm.Builder
{
    /// <summary>
    /// Class for an NTLM authentication authentication token builder.
    /// </summary>
    public sealed class NtlmAuthenticateAuthenticationTokenV2Builder : NtlmAuthenticateAuthenticationTokenBuilderBase
    {
        #region Public Properties
        /// <summary>
        /// NT Proof Response.
        /// </summary>
        public byte[] NTProofResponse { get; set; }
        /// <summary>
        /// Challenge version.
        /// </summary>
        public byte ChallengeVersion { get; set; }
        /// <summary>
        /// Maximum challenge version.
        /// </summary>
        public byte MaxChallengeVersion { get; set; }
        /// <summary>
        /// Reserved field.
        /// </summary>
        public ushort Reserved1 { get; set; }
        /// <summary>
        /// Reserved field.
        /// </summary>
        public uint Reserved2 { get; set; }
        /// <summary>
        /// Timestamp.
        /// </summary>
        public long Timestamp { get; set; }
        /// <summary>
        /// Client challenge.
        /// </summary>
        public byte[] ClientChallenge { get; set; }
        /// <summary>
        /// Reserved field.
        /// </summary>
        public uint Reserved3 { get; set; }
        /// <summary>
        /// NTLM Target Information.
        /// </summary>
        public List<NtlmAvPair> TargetInfo { get; }
        #endregion

        #region Public Methods
        /// <summary>
        /// Calculate the NtProofResponse.
        /// </summary>
        /// <param name="nt_owf_v2">The NTOWFv2 hash for the user.</param>
        /// <param name="server_challenge">The 8 byte server challenge from the CHALLENGE token.</param>
        public void CalculateNtProofResponse(byte[] nt_owf_v2, byte[] server_challenge)
        {
            if (server_challenge is null)
                throw new ArgumentNullException(nameof(server_challenge));
            if (server_challenge.Length != 8)
                throw new ArgumentOutOfRangeException(nameof(server_challenge), "Server challenge should be 8 bytes in size.");
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            writer.Write(server_challenge);
            SerializeNTLMv2Challenge(writer);
            NTProofResponse = new HMACMD5(nt_owf_v2).ComputeHash(stm.ToArray());
        }

        /// <summary>
        /// Calculate the NtProofResponse.
        /// </summary>
        /// <param name="credentials">The NTLMv2 credentials.</param>
        /// <param name="server_challenge">The 8 byte server challenge from the CHALLENGE token.</param>
        public void CalculateNtProofResponse(NtHashAuthenticationCredentials credentials, byte[] server_challenge)
        {
            if (credentials is null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            CalculateNtProofResponse(credentials.NtOWFv2(), server_challenge);
        }

        /// <summary>
        /// Calculate the NtProofResponse.
        /// </summary>
        /// <param name="credentials">The user's credentials.</param>
        /// <param name="server_challenge">The 8 byte server challenge from the CHALLENGE token.</param>
        public void CalculateNtProofResponse(UserCredentials credentials, byte[] server_challenge)
        {
            CalculateNtProofResponse(new NtHashAuthenticationCredentials(credentials), server_challenge);
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        public NtlmAuthenticateAuthenticationTokenV2Builder()
        {
            ChallengeVersion = 1;
            MaxChallengeVersion = 1;
            TargetInfo = new List<NtlmAvPair>();
        }
        #endregion

        #region Private Members
        private void SerializeNTLMv2Challenge(BinaryWriter writer)
        {
            writer.Write(ChallengeVersion);
            writer.Write(MaxChallengeVersion);
            writer.Write(Reserved1);
            writer.Write(Reserved2);
            writer.Write(Timestamp);
            if (ClientChallenge == null && ClientChallenge.Length != 8)
                throw new ArgumentException("Client challenge must be 8 bytes long.", nameof(ClientChallenge));
            writer.Write(ClientChallenge);
            writer.Write(Reserved3);
            TargetInfo.SerializeAvPairs(writer);
            writer.Write(0);
        }

        private protected override byte[] GetNtChallenge()
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);

            if (NTProofResponse == null && NTProofResponse.Length != 16)
                throw new ArgumentException("NT proof response must be 16 bytes long.", nameof(NTProofResponse));

            writer.Write(NTProofResponse);
            SerializeNTLMv2Challenge(writer);
            return stm.ToArray();
        }
        #endregion
    }
}
