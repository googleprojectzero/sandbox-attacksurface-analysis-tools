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
using System.IO;

namespace NtApiDotNet.Win32.Security.Authentication.Ntlm.Builder
{
    /// <summary>
    /// Class to build an NTLM negotiate authentication token.
    /// </summary>
    public sealed class NtlmNegotiateAuthenticationTokenBuilder : NtlmAuthenticationTokenBuilder
    {
        #region Public Properties
        /// <summary>
        /// Domain name.
        /// </summary>
        public string Domain { get; set; }
        /// <summary>
        /// Workstation name.
        /// </summary>
        public string Workstation { get; set; }
        /// <summary>
        /// NTLM version.
        /// </summary>
        public Version Version { get; set; }
        #endregion

        private const int BASE_OFFSET = 40;

        private protected override byte[] GetBytes()
        {
            var flags = Flags & ~(NtlmNegotiateFlags.OemDomainSupplied | NtlmNegotiateFlags.OemWorkstationSupplied | NtlmNegotiateFlags.Version);
            if (Domain != null)
                flags |= NtlmNegotiateFlags.OemDomainSupplied;
            if (Workstation != null)
                flags |= NtlmNegotiateFlags.OemWorkstationSupplied;
            if (Version != null)
                flags |= NtlmNegotiateFlags.Version;

            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            MemoryStream payload = new MemoryStream();
            writer.Write((uint)flags);
            writer.WriteString(Domain, false, BASE_OFFSET, payload);
            writer.WriteString(Workstation, false, BASE_OFFSET, payload);
            writer.WriteVersion(Version);
            writer.Write(payload.ToArray());
            return stm.ToArray();
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public NtlmNegotiateAuthenticationTokenBuilder() : base(NtlmMessageType.Negotiate)
        {
        }
    }
}
