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
using System.Linq;
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

        public KerberosAuthenticationKey Key { get; set; }

        private readonly byte[] _data;

        private int _version;

        private KerberosAuthorizationDataPAC(IEnumerable<KerberosAuthorizationDataPACEntry> entries, byte[] data, int version)
                : base(KerberosAuthorizationDataType.AD_WIN2K_PAC)
        {
            Entries = entries.ToList().AsReadOnly();
            _data = data;
            _version = version;
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
            int count = reader.ReadInt32();
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
            for (int i = 0; i < count; ++i)
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
                    case KerberosAuthorizationDataPACEntryType.TicketChecksum:
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

            auth_data = new KerberosAuthorizationDataPAC(entries.AsReadOnly(), data, version);
            return true;
        }

        private protected byte[] _Encode(int version, IEnumerable<KerberosAuthorizationDataPACEntry> entries)
        {
            MemoryStream stream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stream);

            writer.Write(Entries.Count);
            writer.Write(_version);

            // sizeof(PACTYPE) + sizeof(PAC_INFO_BUFFER) * EntryCount
            long offset = 8 + 16 * Entries.Count;

            foreach (var entry in Entries)
            {
                var entryData = entry.Data;
                if (entry is KerberosAuthorizationDataPACLogon ||
                    entry is KerberosAuthorizationDataPACSignature)
                {
                    entryData = entry.Encode();
                }

                // Write the PAC_INFO_BUFFER
                writer.Write((int)entry.PACType);
                writer.Write(entryData.Length);
                writer.Write(offset);

                // Write the actual data
                int current = (int)writer.BaseStream.Position;
                writer.BaseStream.Position = offset;
                writer.Write(entryData); 
                offset = (offset + entryData.Length + 7) / 8 * 8;
                while (writer.BaseStream.Position < offset)
                {
                    // MS always rounds data boundaries
                    writer.Write('\x00');
                }
                writer.BaseStream.Position = current;
            }

            var t1 = BitConverter.ToString(stream.ToArray()).Replace("-", "");
            var t2 = BitConverter.ToString(_data).Replace("-", "");

            return stream.ToArray();
        }

        private protected byte[] Encode()
        {
            if (Key == null)
            {
                return _Encode(_version, Entries);
            }

            // Re-calculate checksums - we're only assuming we have the service key (not KDC)

            var entries = new List<KerberosAuthorizationDataPACEntry>(Entries);

            var serverChecksum = entries.First(e => e.PACType == KerberosAuthorizationDataPACEntryType.ServerChecksum) as KerberosAuthorizationDataPACSignature;
            var kdcChecksum = entries.First(e => e.PACType == KerberosAuthorizationDataPACEntryType.KDCChecksum) as KerberosAuthorizationDataPACSignature;
            var ticketChecksum = entries.FirstOrDefault(e => e.PACType == KerberosAuthorizationDataPACEntryType.TicketChecksum) as KerberosAuthorizationDataPACSignature;

            byte[] serverChecksumSignature = serverChecksum.Signature;
            byte[] kdcChecksumSignature = kdcChecksum.Signature;
            
            serverChecksum.Signature = new byte[serverChecksum.Signature.Length];
            kdcChecksum.Signature = new byte[kdcChecksum.Signature.Length];

            byte[] ticketChecksumSignature = null;
            if (ticketChecksum != null)
            {
                ticketChecksumSignature = ticketChecksum.Signature;
                ticketChecksum.Signature = new byte[ticketChecksum.Signature.Length];
            }
                
            byte[] encodedForHashing = _Encode(_version, entries);

            serverChecksum.Signature = KerberosChecksum.Create(Key, encodedForHashing, 0, encodedForHashing.Length, KerberosKeyUsage.KerbNonKerbChksumSalt).Checksum;
            kdcChecksum.Signature = kdcChecksumSignature;

            if (ticketChecksumSignature != null)
            {
                ticketChecksum.Signature = ticketChecksumSignature;
            }

            return _Encode(_version, entries);
        }

        private protected override byte[] GetData()
        {
            return Encode();
        }
    }
}
