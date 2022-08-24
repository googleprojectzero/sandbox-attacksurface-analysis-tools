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

using NtApiDotNet.Utilities.Text;
using System.IO;

namespace NtApiDotNet.Win32.Security.Authentication.Ntlm.Builder
{
    /// <summary>
    /// Base class for an NTLM authentication token builder.
    /// </summary>
    public abstract class NtlmAuthenticationTokenBuilder
    {
        /// <summary>
        /// Type of NTLM message.
        /// </summary>
        public NtlmMessageType MessageType { get; }

        /// <summary>
        /// NTLM negotitation flags.
        /// </summary>
        public NtlmNegotiateFlags Flags { get; set; }

        /// <summary>
        /// Get or set whether the token should be unicode.
        /// </summary>
        public bool Unicode
        {
            get => Flags.HasFlagSet(NtlmNegotiateFlags.Unicode);
            set
            {
                if (value)
                    Flags |= NtlmNegotiateFlags.Unicode;
                else
                    Flags &= ~NtlmNegotiateFlags.Unicode;
            }
        }

        private protected NtlmAuthenticationTokenBuilder(NtlmMessageType message_type)
        {
            MessageType = message_type;
        }

        private protected abstract byte[] GetBytes();

        /// <summary>
        /// Create an authentication token from the builder.
        /// </summary>
        /// <returns>The NTLM authentication token.</returns>
        public NtlmAuthenticationToken Create()
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);

            writer.Write(BinaryEncoding.Instance.GetBytes(NtlmUtilsInternal.NTLM_MAGIC));
            writer.Write((int)MessageType);
            writer.Write(GetBytes());

            return NtlmAuthenticationToken.Parse(stm.ToArray());
        }
    }
}
