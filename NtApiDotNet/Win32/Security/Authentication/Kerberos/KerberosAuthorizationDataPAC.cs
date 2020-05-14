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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent AD_WIN2K_PAC type.
    /// </summary>
    public class KerberosAuthorizationDataPAC : KerberosAuthorizationData
    {
        /// <summary>
        /// List of PAC entries.
        /// </summary>
        public IReadOnlyList<KerberosAuthorizationDataPACEntry> Entries { get; }

        private KerberosAuthorizationDataPAC(byte[] data, IReadOnlyList<KerberosAuthorizationDataPACEntry> entries)
                : base(KerberosAuthorizationDataType.AD_WIN2K_PAC, data)
        {
            Entries = entries;
        }

        private protected override void FormatData(StringBuilder builder)
        {
            foreach (var entry in Entries)
            {
                entry.Format(builder);
            }
        }

        internal static bool Parse(byte[] data, out KerberosAuthorizationDataPAC auth_data)
        {
            auth_data = null;
            if (data.Length < 8)
                return false;
            BinaryReader reader = new BinaryReader(new MemoryStream(data));
            long count = reader.ReadInt32();
            int version = reader.ReadInt32();
            if (version != 0)
            {
                return false;
            }
            if (reader.RemainingLength() < count * 16)
            {
                return false;
            }

            List<KerberosAuthorizationDataPACEntry> entries = new List<KerberosAuthorizationDataPACEntry>();
            for (long i = 0; i < count; ++i)
            {
                int type = reader.ReadInt32();
                int length = reader.ReadInt32();
                long offset = reader.ReadInt64();

                if (offset >= data.LongLength || (offset + length) > data.LongLength)
                {
                    return false;
                }

                byte[] entry_data = new byte[length];
                Buffer.BlockCopy(data, (int)offset, entry_data, 0, length);

                KerberosAuthorizationDataPACEntryType entry_type = (KerberosAuthorizationDataPACEntryType)type;
                KerberosAuthorizationDataPACEntry pac_entry = null;
                switch (entry_type)
                {
                    case KerberosAuthorizationDataPACEntryType.UserClaims:
                    case KerberosAuthorizationDataPACEntryType.DeviceClaims:
                        if (!KerberosAuthorizationDataPACClaimSet.Parse(entry_type, entry_data, out pac_entry))
                            pac_entry = null;
                        break;
                    case KerberosAuthorizationDataPACEntryType.KDCChecksum:
                    case KerberosAuthorizationDataPACEntryType.ServerChecksum:
                        if (!KerberosAuthorizationDataPACSignature.Parse(entry_type, entry_data, out pac_entry))
                            pac_entry = null;
                        break;
                    case KerberosAuthorizationDataPACEntryType.ClientInfo:
                        if (!KerberosAuthorizationDataPACClientInfo.Parse(entry_type, entry_data, out pac_entry))
                            pac_entry = null;
                        break;
                    case KerberosAuthorizationDataPACEntryType.UserPrincipalName:
                        if (!KerberosAuthorizationDataPACUpnDnsInfo.Parse(entry_type, entry_data, out pac_entry))
                            pac_entry = null;
                        break;
                    case KerberosAuthorizationDataPACEntryType.Logon:
                        if (!KerberosAuthorizationDataPACLogon.Parse(entry_type, entry_data, out pac_entry))
                            pac_entry = null;
                        break;
                    case KerberosAuthorizationDataPACEntryType.Device:
                        if (!KerberosAuthorizationDataPACDevice.Parse(entry_data, out pac_entry))
                            pac_entry = null;
                        break;
                }

                if (pac_entry == null)
                {
                    pac_entry = new KerberosAuthorizationDataPACEntry(entry_type, entry_data);
                }

                entries.Add(pac_entry);
            }

            auth_data = new KerberosAuthorizationDataPAC(data, entries.AsReadOnly());
            return true;
        }
    }
}
