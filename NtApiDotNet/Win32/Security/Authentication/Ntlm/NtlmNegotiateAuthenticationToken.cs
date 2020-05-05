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
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Ntlm
{
    /// <summary>
    /// Class to represent an NTLM NEGOTIATE token.
    /// </summary>
    public sealed class NtlmNegotiateAuthenticationToken : NtlmAuthenticationToken
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
        /// NTLM version.
        /// </summary>
        public Version Version { get; }
        #endregion

        #region Public Methods
        /// <summary>
        /// Format the authentication token.
        /// </summary>
        /// <returns>The formatted token.</returns>
        public override string Format()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine("<NTLM NEGOTIATE>");
            builder.AppendLine($"Flags: {Flags}");
            if (!string.IsNullOrEmpty(Domain))
            {
                builder.AppendLine($"Domain: {Domain}");
            }
            if (!string.IsNullOrEmpty(Workstation))
            {
                builder.AppendLine($"Workstation: {Workstation}");
            }
            builder.AppendLine($"Version: {Version}");
            return builder.ToString();
        }
        #endregion

        #region Constructors
        private NtlmNegotiateAuthenticationToken(byte[] data, NtlmNegotiateFlags flags, string domain, 
            string workstation, Version version)
            : base(data, NtlmMessageType.Negotiate, flags)
        {
            Domain = domain;
            Workstation = workstation;
            Version = version;
        }
        #endregion

        #region Internal Methods
        internal static bool TryParse(byte[] data, BinaryReader reader, out NtlmAuthenticationToken token)
        {
            token = null;
            NtlmNegotiateFlags flags = (NtlmNegotiateFlags)reader.ReadInt32();
            if (!NtlmUtils.ParseString(NtlmNegotiateFlags.Oem, reader, 
                data, flags.HasFlagSet(NtlmNegotiateFlags.OemDomainSupplied), 
                out string domain))
            {
                return false;
            }
            if (!NtlmUtils.ParseString(NtlmNegotiateFlags.Oem, reader,
                data, flags.HasFlagSet(NtlmNegotiateFlags.OemWorkstationSupplied),
                out string workstation))
            {
                return false;
            }
            if (!NtlmUtils.TryParse(reader, out Version version))
                return false;

            token = new NtlmNegotiateAuthenticationToken(data, flags, domain, workstation, version);
            return true;
        }
        #endregion
    }
}
