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
#pragma warning disable 1591
    /// <summary>
    /// The type of the AV_PAIR.
    /// </summary>
    public enum MsAvPairType
    {
        EOL = 0x0000,
        NbComputerName = 0x0001,
        NbDomainName = 0x0002,
        DnsComputerName = 0x0003,
        DnsDomainName = 0x0004,
        DnsTreeName = 0x0005,
        Flags = 0x0006,
        Timestamp = 0x0007,
        SingleHost = 0x0008,
        TargetName = 0x0009,
        ChannelBindings = 0x000A,
    }

    /// <summary>
    /// MS AV Flags.
    /// </summary>
    [Flags]
    public enum MsvAvFlags
    {
        None = 0,
        Constrained = 1,
        MessageIntegrity = 2,
        TargetSPNUntrusted = 4,
    }

#pragma warning restore

    /// <summary>
    /// An NTLM AV_PAIR.
    /// </summary>
    public abstract class NtlmAvPair
    {
        /// <summary>
        /// The type of the AV Pair value.
        /// </summary>
        public MsAvPairType Type { get; }

        internal static bool TryParse(BinaryReader reader, out NtlmAvPair av_pair)
        {
            av_pair = null;
            if (reader.RemainingLength() < 4)
                return false;
            MsAvPairType type = (MsAvPairType)reader.ReadInt16();
            int length = reader.ReadUInt16();

            if (reader.RemainingLength() < length)
                return false;

            switch (type)
            {
                case MsAvPairType.DnsComputerName:
                case MsAvPairType.DnsDomainName:
                case MsAvPairType.DnsTreeName:
                case MsAvPairType.NbComputerName:
                case MsAvPairType.NbDomainName:
                case MsAvPairType.TargetName:
                    if ((length % 1) != 0)
                        return false;
                    av_pair = new NtlmAvPairString(type, Encoding.Unicode.GetString(reader.ReadBytes(length)));
                    break;
                case MsAvPairType.Timestamp:
                    if (length != 8)
                        return false;
                    av_pair = new NtlmAvPairTimestamp(type, reader.ReadInt64());
                    break;
                case MsAvPairType.Flags:
                    if (length != 4)
                        return false;
                    av_pair = new NtlmAvPairFlags(type, reader.ReadInt32());
                    break;
                case MsAvPairType.SingleHost:
                    if (length != 48)
                        return false;
                    reader.ReadInt32();
                    uint z4 = reader.ReadUInt32();
                    byte[] custom_data = reader.ReadBytes(8);
                    byte[] machine_id = reader.ReadBytes(32);
                    av_pair = new NtlmAvPairSingleHostData(type, z4, custom_data, machine_id);
                    break;
                default:
                    av_pair = new NtlmAvPairBytes(type, reader.ReadBytes(length));
                    break;
            }
            return true;
        }

        internal NtlmAvPair(MsAvPairType type)
        {
            Type = type;
        }
    }

    /// <summary>
    /// An NTLM AV_PAIR with a string value.
    /// </summary>
    public sealed class NtlmAvPairString : NtlmAvPair
    {
        /// <summary>
        /// The string value.
        /// </summary>
        public string Value { get; }

        internal NtlmAvPairString(MsAvPairType type, string value) 
            : base(type)
        {
            Value = value;
        }

        /// <summary>
        /// ToString method.
        /// </summary>
        /// <returns>Pair as a string.</returns>
        public override string ToString()
        {
            return $"{Type} - {Value}";
        }
    }

    /// <summary>
    /// An NTLM AV_PAIR with a timestamp value;
    /// </summary>
    public sealed class NtlmAvPairTimestamp : NtlmAvPair
    {
        /// <summary>
        /// The timestamp value.
        /// </summary>
        public DateTime Value { get; }

        internal NtlmAvPairTimestamp(MsAvPairType type, long value)
            : base(type)
        {
            Value = DateTime.FromFileTime(value);
        }

        /// <summary>
        /// ToString method.
        /// </summary>
        /// <returns>Pair as a string.</returns>
        public override string ToString()
        {
            return $"{Type} - {Value}";
        }
    }

    /// <summary>
    /// An NTLM AV_PAIR with a bytes value.
    /// </summary>
    public sealed class NtlmAvPairBytes : NtlmAvPair
    {
        /// <summary>
        /// The value.
        /// </summary>
        public byte[] Value { get; }

        internal NtlmAvPairBytes(MsAvPairType type, byte[] value)
            : base(type)
        {
            Value = value;
        }

        /// <summary>
        /// ToString method.
        /// </summary>
        /// <returns>Pair as a string.</returns>
        public override string ToString()
        {
            return $"{Type} - {NtObjectUtils.ToHexString(Value)}";
        }
    }

    /// <summary>
    /// An NTLM AV_PAIR with a flags value.
    /// </summary>
    public sealed class NtlmAvPairFlags : NtlmAvPair
    {
        /// <summary>
        /// The value.
        /// </summary>
        public MsvAvFlags Value { get; }

        internal NtlmAvPairFlags(MsAvPairType type, int value)
            : base(type)
        {
            Value = (MsvAvFlags)value;
        }

        /// <summary>
        /// ToString method.
        /// </summary>
        /// <returns>Pair as a string.</returns>
        public override string ToString()
        {
            return $"{Type} - {Value}";
        }
    }

    /// <summary>
    /// An NTLM AV_PAIR with a flags value.
    /// </summary>
    public sealed class NtlmAvPairSingleHostData : NtlmAvPair
    {
        /// <summary>
        /// The the Z4 data.
        /// </summary>
        public uint Z4 { get; }

        /// <summary>
        /// Custom data blob.
        /// </summary>
        public byte[] CustomData { get; }

        /// <summary>
        /// Machine ID.
        /// </summary>
        public byte[] MachineId { get; }

        internal NtlmAvPairSingleHostData(MsAvPairType type, uint z4, byte[] custom_data, byte[] machine_id)
            : base(type)
        {
            Z4 = z4;
            CustomData = custom_data;
            MachineId = machine_id;
        }

        /// <summary>
        /// ToString method.
        /// </summary>
        /// <returns>Pair as a string.</returns>
        public override string ToString()
        {
            return $"{Type} - Z4 0x{Z4:X} - Custom Data: {NtObjectUtils.ToHexString(CustomData)} Machine ID: {NtObjectUtils.ToHexString(MachineId)}";
        }
    }
}
