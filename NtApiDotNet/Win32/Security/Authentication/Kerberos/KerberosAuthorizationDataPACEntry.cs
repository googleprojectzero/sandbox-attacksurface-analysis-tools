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
using NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
#pragma warning disable 1591
    /// <summary>
    /// Type for the PAC Entry.
    /// </summary>
    public enum KerberosAuthorizationDataPACEntryType
    {
        Logon = 1,
        Credentials = 2,
        ServerChecksum = 6,
        KDCChecksum = 7,
        ClientInfo = 0xA,
        ConstrainedDelegation = 0xB,
        UserPrincipalName = 0xC,
        UserClaims = 0xD,
        Device = 0xE,
        DeviceClaims = 0xF,
        TicketChecksum = 0x10,
        Attributes = 0x11,
        Requestor = 0x12,
        FullPacChecksum = 0x13
    }
#pragma warning restore 1591

    /// <summary>
    /// Single PAC Entry.
    /// </summary>
    public class KerberosAuthorizationDataPACEntry
    {
        /// <summary>
        /// Type of PAC entry.
        /// </summary>
        public KerberosAuthorizationDataPACEntryType PACType { get; }
        /// <summary>
        /// The PAC data.
        /// </summary>
        public byte[] Data { get; }

        /// <summary>
        /// Convert the entry into a builder.
        /// </summary>
        /// <returns>The builder entry.</returns>
        public virtual KerberosAuthorizationDataPACEntryBuilder ToBuilder()
        {
            return new KerberosAuthorizationDataPACEntryRawBuilder(this);
        }

        internal KerberosAuthorizationDataPACEntry(KerberosAuthorizationDataPACEntryType type, byte[] data)
        {
            PACType = type;
            Data = data;
        }

        private protected virtual void FormatData(StringBuilder builder)
        {
            HexDumpBuilder hex = new HexDumpBuilder(false, true, true, false, 0);
            hex.Append(Data);
            hex.Complete();
            builder.Append(hex.ToString());
        }

        internal void Format(StringBuilder builder)
        {
            builder.AppendLine($"<PAC Entry {PACType}>");
            FormatData(builder);
            builder.AppendLine();
        }
    }
}
