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

using NtApiDotNet.Utilities.ASN1;
using NtApiDotNet.Utilities.ASN1.Builder;
using System;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Flags for KerberosAuthorizationDataRestrictionEntry
    /// </summary>
    [Flags]
    public enum KerberosRestrictionEntryFlags
    {
        /// <summary>
        /// Full UAC token.
        /// </summary>
        FullToken = 0,
        /// <summary>
        /// Limited UAC token.
        /// </summary>
        LimitedToken = 1,
    }

    /// <summary>
    /// Class to represent the KERB_AD_RESTRICTION_ENTRY AD type.
    /// </summary>
    public sealed class KerberosAuthorizationDataRestrictionEntry : KerberosAuthorizationData
    {
        /// <summary>
        /// Flags.
        /// </summary>
        public KerberosRestrictionEntryFlags Flags { get; }
        /// <summary>
        /// Token IL.
        /// </summary>
        public TokenIntegrityLevel IntegrityLevel { get; }
        /// <summary>
        /// Machine ID.
        /// </summary>
        public byte[] MachineId { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="flags">The restriction flags.</param>
        /// <param name="integrity_level">The integrity level.</param>
        /// <param name="machine_id">The originating machine ID.</param>
        public KerberosAuthorizationDataRestrictionEntry(KerberosRestrictionEntryFlags flags,
            TokenIntegrityLevel integrity_level, byte[] machine_id) : base(KerberosAuthorizationDataType.KERB_AD_RESTRICTION_ENTRY)
        {
            if (machine_id is null)
            {
                throw new ArgumentNullException(nameof(machine_id));
            }

            if (machine_id.Length != 32)
                throw new ArgumentException("Machine ID must be 32 bytes in length.", nameof(machine_id));

            Flags = flags;
            IntegrityLevel = integrity_level;
            MachineId = (byte[])machine_id.Clone();
        }

        private protected override void FormatData(StringBuilder builder)
        {
            builder.AppendLine($"Flags           : {Flags}");
            builder.AppendLine($"Integrity Level : {IntegrityLevel}");
            builder.AppendLine($"Machine ID      : {NtObjectUtils.ToHexString(MachineId)}");
        }

        private protected override byte[] GetData()
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            writer.Write((int)Flags);
            writer.Write((int)IntegrityLevel);
            writer.Write(MachineId);

            DERBuilder builder = new DERBuilder();
            using (var seq1 = builder.CreateSequence())
            {
                using (var seq2 = seq1.CreateSequence())
                {
                    seq2.WriteContextSpecific(0, 0);
                    seq2.WriteContextSpecific(1, stm.ToArray());
                }
            }

            return builder.ToArray();
        }

        internal static bool Parse(byte[] data, out KerberosAuthorizationDataRestrictionEntry entry)
        {
            entry = null;
            DERValue[] values = DERParser.ParseData(data, 0);
            if (!values.CheckValueSequence())
                return false;
            values = values[0].Children;
            if (!values.CheckValueSequence())
                return false;
            byte[] lsap_data = null;
            try
            {
                foreach (var next in values[0].Children)
                {
                    if (next.Type != DERTagType.ContextSpecific)
                        return false;
                    switch (next.Tag)
                    {
                        case 0:
                            if (next.ReadChildInteger() != 0)
                                return false;
                            // Should always be 0.
                            break;
                        case 1:
                            lsap_data = next.ReadChildOctetString();
                            break;
                    }
                }
            }
            catch (InvalidDataException)
            {
                return false;
            }

            if (lsap_data == null || lsap_data.Length != 40)
                return false;
            int flags = BitConverter.ToInt32(lsap_data, 0);
            int il = BitConverter.ToInt32(lsap_data, 4);
            byte[] machine_id = new byte[32];
            Buffer.BlockCopy(lsap_data, 8, machine_id, 0, 32);
            entry = new KerberosAuthorizationDataRestrictionEntry((KerberosRestrictionEntryFlags)flags, (TokenIntegrityLevel)il, machine_id);
            return true;
        }
    }
}
