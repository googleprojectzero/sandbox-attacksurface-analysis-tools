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

using System;
using System.Collections.Generic;
using System.IO;

namespace NtApiDotNet.Win32.Security.Authentication.Ntlm.Builder
{
    /// <summary>
    /// Class to build an NTLM challenge authentication token.
    /// </summary>
    public sealed class NtlmChallengeAuthenticationTokenBuilder : NtlmAuthenticationTokenBuilder
    {
        #region Public Properties
        /// <summary>
        /// Target name.
        /// </summary>
        public string TargetName { get; set; }
        /// <summary>
        /// Server challenge.
        /// </summary>
        public byte[] ServerChallenge { get; set; }
        /// <summary>
        /// Reserved.
        /// </summary>
        public byte[] Reserved { get; set; }
        /// <summary>
        /// NTLM version.
        /// </summary>
        public Version Version { get; set; }
        /// <summary>
        /// NTLM Target Information.
        /// </summary>
        public List<NtlmAvPair> TargetInfo { get; }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        public NtlmChallengeAuthenticationTokenBuilder() : base(NtlmMessageType.Challenge)
        {
            TargetInfo = new List<NtlmAvPair>();
        }
        #endregion

        #region Private Members
        private const int BASE_OFFSET = 56;

        private protected override byte[] GetBytes()
        {
            var flags = Flags & ~(NtlmNegotiateFlags.RequestTarget | NtlmNegotiateFlags.TargetInfo | NtlmNegotiateFlags.Version);
            bool unicode = flags.HasFlagSet(NtlmNegotiateFlags.Unicode);
            if (TargetName != null)
                flags |= NtlmNegotiateFlags.RequestTarget;
            if (TargetInfo.Count > 0)
                flags |= NtlmNegotiateFlags.TargetInfo;
            if (Version != null)
                flags |= NtlmNegotiateFlags.Version;

            byte[] challenge = ServerChallenge ?? new byte[8];
            byte[] reserved = Reserved ?? new byte[8];

            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            MemoryStream payload = new MemoryStream();
            writer.WriteString(TargetName, unicode, BASE_OFFSET, payload);
            writer.Write((uint)flags);
            writer.Write(challenge, 0, 8);
            writer.Write(reserved, 0, 8);
            writer.WriteBinary(TargetInfo.SerializeAvPairs(), BASE_OFFSET, payload);
            writer.WriteVersion(Version);
            writer.Write(payload.ToArray());
            return stm.ToArray();
        }
        #endregion
    }
}
