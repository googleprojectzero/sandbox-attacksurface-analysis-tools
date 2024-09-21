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

using NtApiDotNet.Net;
using NtApiDotNet.Utilities.Data;
using System;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder
{
    /// <summary>
    /// Class to represent a UPN_DNS_INFO builder.
    /// </summary>
    public sealed class KerberosAuthorizationDataPACUpnDnsInfoBuilder : KerberosAuthorizationDataPACEntryBuilder
    {
        /// <summary>
        /// Flags.
        /// </summary>
        public KerberosUpnDnsInfoFlags Flags { get; set; }
        /// <summary>
        /// The User Principal Name.
        /// </summary>
        public string UserPrincipalName { get; set; }
        /// <summary>
        /// The DNS Domain Name.
        /// </summary>
        public string DnsDomainName { get; set; }
        /// <summary>
        /// The user's SAM name.
        /// </summary>
        public string SamName { get; set; }
        /// <summary>
        /// The user's SID.
        /// </summary>
        public Sid Sid { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public KerberosAuthorizationDataPACUpnDnsInfoBuilder() 
            : base(KerberosAuthorizationDataPACEntryType.UserPrincipalName)
        {
        }

        internal KerberosAuthorizationDataPACUpnDnsInfoBuilder(KerberosAuthorizationDataPACUpnDnsInfo info) : this()
        {
            Flags = info.Flags;
            UserPrincipalName = info.UserPrincipalName;
            DnsDomainName = info.DnsDomainName;
            SamName = info.SamName;
            Sid = info.Sid;
        }

        /// <summary>
        /// Create the real PAC entry.
        /// </summary>
        /// <returns>The created PAC entry.</returns>
        public override KerberosAuthorizationDataPACEntry Create()
        {
            if (string.IsNullOrEmpty(UserPrincipalName))
                throw new ArgumentNullException(nameof(UserPrincipalName));
            if (string.IsNullOrEmpty(DnsDomainName))
                throw new ArgumentNullException(nameof(DnsDomainName));

            DataWriter writer = new DataWriter();

            int data_offset = 12;
            if (Flags.HasFlagSet(KerberosUpnDnsInfoFlags.Extended))
            {
                data_offset += 8;
                if (string.IsNullOrEmpty(SamName))
                    throw new ArgumentNullException(nameof(SamName));
                if (Sid is null)
                    throw new ArgumentNullException(nameof(Sid));
            }

            data_offset += KerberosBuilderUtils.GetAlignment(data_offset, 8);

            WriteBuffer(writer, UserPrincipalName, ref data_offset, 8);
            // The DNS domain name doesn't seem to be aligned in the Windows implementation.
            WriteBuffer(writer, DnsDomainName, ref data_offset, 1);
            writer.Write((int)Flags);
            if (Flags.HasFlagSet(KerberosUpnDnsInfoFlags.Extended))
            {
                WriteBuffer(writer, SamName, ref data_offset, 8);
                WriteBuffer(writer, Sid.ToArray(), ref data_offset, 8);
            }

            if (!KerberosAuthorizationDataPACUpnDnsInfo.Parse(writer.ToArray(),
                out KerberosAuthorizationDataPACEntry entry))
            {
                throw new InvalidDataException("Invalid PAC entry.");
            }
            return entry;
        }

        private static void WriteBuffer(DataWriter writer, byte[] data, ref int data_offset, int alignment)
        {
            writer.WriteUInt16(data.Length);
            writer.WriteUInt16(data_offset);

            long pos = writer.BaseStream.Position;
            writer.BaseStream.Position = data_offset;
            writer.Write(data);
            data_offset += data.Length;
            int padding = KerberosBuilderUtils.GetAlignment(data_offset, alignment);
            data_offset += padding;
            writer.Write(new byte[padding]);
            writer.BaseStream.Position = pos;
        }

        private static void WriteBuffer(DataWriter writer, string data, ref int data_offset, int alignment)
        {
            WriteBuffer(writer, Encoding.Unicode.GetBytes(data), ref data_offset, alignment);
        }
    }
}
