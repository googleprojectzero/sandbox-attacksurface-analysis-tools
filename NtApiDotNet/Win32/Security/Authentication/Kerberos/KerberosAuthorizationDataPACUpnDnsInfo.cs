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
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Flags for the UPN_DNS_INFO.
    /// </summary>
    public enum KerberosUpnDnsInfoFlags
    {
        /// <summary>
        /// No flags.
        /// </summary>
        None = 0,
        /// <summary>
        /// The user has no UPN.
        /// </summary>
        NoUpn = 1,
        /// <summary>
        /// The UPN_DNS_INFO has been extended with the SAM name and SID.
        /// </summary>
        Extended,
    }
    
    /// <summary>
    /// Class to represent UPN_DNS_INFO.
    /// </summary>
    public class KerberosAuthorizationDataPACUpnDnsInfo : KerberosAuthorizationDataPACEntry
    {
        /// <summary>
        /// Flags.
        /// </summary>
        public KerberosUpnDnsInfoFlags Flags { get; }
        /// <summary>
        /// The User Principal Name.
        /// </summary>
        public string UserPrincipalName { get; }
        /// <summary>
        /// The DNS Domain Name.
        /// </summary>
        public string DnsDomainName { get; }
        /// <summary>
        /// The user's SAM name.
        /// </summary>
        public string SamName { get; }
        /// <summary>
        /// The user's SID.
        /// </summary>
        public Sid Sid { get; }

        private KerberosAuthorizationDataPACUpnDnsInfo(byte[] data, 
            KerberosUpnDnsInfoFlags flags, string upn, string dns, string sam_name, Sid sid)
            : base(KerberosAuthorizationDataPACEntryType.UserPrincipalName, data)
        {
            Flags = flags;
            UserPrincipalName = upn;
            DnsDomainName = dns;
            SamName = sam_name;
            Sid = sid;
        }

        internal static bool Parse(byte[] data, out KerberosAuthorizationDataPACEntry entry)
        {
            entry = null;
            if (data.Length < 12)
                return false;

            int upn_length = BitConverter.ToUInt16(data, 0);
            int upn_offset = BitConverter.ToUInt16(data, 2);
            int dns_length = BitConverter.ToUInt16(data, 4);
            int dns_offset = BitConverter.ToUInt16(data, 6);
            KerberosUpnDnsInfoFlags flags = (KerberosUpnDnsInfoFlags)BitConverter.ToInt32(data, 8);

            if (upn_length + upn_offset > data.Length || dns_length + dns_offset > data.Length)
                return false;

            string upn = Encoding.Unicode.GetString(data, upn_offset, upn_length);
            string dns = Encoding.Unicode.GetString(data, dns_offset, dns_length);
            string sam_name = string.Empty;
            Sid sid = null;

            if (flags.HasFlagSet(KerberosUpnDnsInfoFlags.Extended))
            {
                if (data.Length < 20)
                    return false;
                int sam_name_length = BitConverter.ToUInt16(data, 12);
                int sam_name_offset = BitConverter.ToUInt16(data, 14);
                int sid_length = BitConverter.ToUInt16(data, 16);
                int sid_offset = BitConverter.ToUInt16(data, 18);
                if (sam_name_length + sam_name_offset > data.Length || sid_length + sid_offset > data.Length)
                    return false;
                sam_name = Encoding.Unicode.GetString(data, sam_name_offset, sam_name_length);
                byte[] sid_bytes = new byte[sid_length];
                Buffer.BlockCopy(data, sid_offset, sid_bytes, 0, sid_length);
                var sid_result = Sid.Parse(sid_bytes, false);
                if (!sid_result.IsSuccess)
                    return false;
                sid = sid_result.Result;
            }

            entry = new KerberosAuthorizationDataPACUpnDnsInfo(data, flags, upn, dns, sam_name, sid);
            return true;
        }

        private protected override void FormatData(StringBuilder builder)
        {
            builder.AppendLine($"Flags            : {Flags}");
            builder.AppendLine($"Name             : {UserPrincipalName}");
            builder.AppendLine($"DNS Name         : {DnsDomainName}");
        }
    }
}
