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

using NtApiDotNet.Utilities.Reflection;
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
        [SDKName("MsvAvEOL")]
        EOL = 0x0000,
        [SDKName("MsvAvNbComputerName")]
        NbComputerName = 0x0001,
        [SDKName("MsvAvNbDomainName")]
        NbDomainName = 0x0002,
        [SDKName("MsvAvDnsComputerName")]
        DnsComputerName = 0x0003,
        [SDKName("MsvAvDnsDomainName")]
        DnsDomainName = 0x0004,
        [SDKName("MsvAvDnsTreeName")]
        DnsTreeName = 0x0005,
        [SDKName("MsvAvFlags")]
        Flags = 0x0006,
        [SDKName("MsvAvTimestamp")]
        Timestamp = 0x0007,
        [SDKName("MsvAvRestrictions")]
        Restrictions = 0x0008,
        [SDKName("MsvAvTargetName")]
        TargetName = 0x0009,
        [SDKName("MsvAvChannelBindings")]
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

        private protected abstract byte[] GetBytes();

        internal void Write(BinaryWriter writer)
        {
            byte[] ba = GetBytes();
            writer.Write((short)Type);
            writer.Write((ushort)ba.Length);
            writer.Write(ba);
        }

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
                    av_pair = new NtlmAvPairTimestamp(reader.ReadInt64());
                    break;
                case MsAvPairType.Flags:
                    if (length != 4)
                        return false;
                    av_pair = new NtlmAvPairFlags((MsvAvFlags)reader.ReadInt32());
                    break;
                case MsAvPairType.Restrictions:
                    if (length != 48)
                        return false;
                    reader.ReadInt32();
                    uint z4 = reader.ReadUInt32();
                    byte[] custom_data = reader.ReadBytes(8);
                    byte[] machine_id = reader.ReadBytes(32);
                    av_pair = new NtlmAvPairSingleHostData(z4, custom_data, machine_id);
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

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="type">The type of the string.</param>
        /// <param name="value">The string value.</param>
        public NtlmAvPairString(MsAvPairType type, string value) 
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

        /// <summary>
        /// Create a DNS computer name AV pair.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <returns>The AV pair.</returns>
        public static NtlmAvPairString CreateDnsComputerName(string name)
        {
            return new NtlmAvPairString(MsAvPairType.DnsComputerName, name);
        }

        /// <summary>
        /// Create a DNS domain name AV pair.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <returns>The AV pair.</returns>
        public static NtlmAvPairString CreateDnsDomainName(string name)
        {
            return new NtlmAvPairString(MsAvPairType.DnsDomainName, name);
        }

        /// <summary>
        /// Create a DNS tree name AV pair.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <returns>The AV pair.</returns>
        public static NtlmAvPairString CreateDnsTreeName(string name)
        {
            return new NtlmAvPairString(MsAvPairType.DnsTreeName, name);
        }

        /// <summary>
        /// Create a NETBIOS computer name AV pair.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <returns>The AV pair.</returns>
        public static NtlmAvPairString CreateNbComputerName(string name)
        {
            return new NtlmAvPairString(MsAvPairType.NbComputerName, name);
        }

        /// <summary>
        /// Create a NETBIOS domain name AV pair.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <returns>The AV pair.</returns>
        public static NtlmAvPairString CreateNbDomainName(string name)
        {
            return new NtlmAvPairString(MsAvPairType.NbDomainName, name);
        }

        /// <summary>
        /// Create a target name AV pair.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <returns>The AV pair.</returns>
        public static NtlmAvPairString CreateTargetName(string name)
        {
            return new NtlmAvPairString(MsAvPairType.TargetName, name);
        }

        private protected override byte[] GetBytes()
        {
            return Encoding.Unicode.GetBytes(Value);
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

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="value"></param>
        public NtlmAvPairTimestamp(long value)
            : base(MsAvPairType.Timestamp)
        {
            try
            {
                Value = DateTime.FromFileTime(value);
            }
            catch (ArgumentOutOfRangeException)
            {
                Value = DateTime.MinValue;
            }
        }

        /// <summary>
        /// ToString method.
        /// </summary>
        /// <returns>Pair as a string.</returns>
        public override string ToString()
        {
            return $"{Type} - {Value}";
        }

        private protected override byte[] GetBytes()
        {
            return BitConverter.GetBytes(Value.ToFileTime());
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

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="type">The type value.</param>
        /// <param name="value">The raw bytes value.</param>
        public NtlmAvPairBytes(MsAvPairType type, byte[] value)
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

        private protected override byte[] GetBytes()
        {
            return Value;
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

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="value">The flags.</param>
        public NtlmAvPairFlags(MsvAvFlags value)
            : base(MsAvPairType.Flags)
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

        private protected override byte[] GetBytes()
        {
            return BitConverter.GetBytes((int)Value);
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

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="z4">The Z4 value.</param>
        /// <param name="custom_data">Custom data value.</param>
        /// <param name="machine_id">Machine ID</param>
        public NtlmAvPairSingleHostData(uint z4, byte[] custom_data, byte[] machine_id)
            : base(MsAvPairType.Restrictions)
        {
            Z4 = z4;
            CustomData = custom_data ?? throw new ArgumentNullException(nameof(custom_data));
            if (CustomData.Length != 8)
                throw new ArgumentException("CustomData must be 8 bytes in length.");
            MachineId = machine_id ?? throw new ArgumentNullException(nameof(machine_id));
            if (MachineId.Length != 32)
                throw new ArgumentException("CustomData must be 32 bytes in length.");
        }

        /// <summary>
        /// ToString method.
        /// </summary>
        /// <returns>Pair as a string.</returns>
        public override string ToString()
        {
            return $"{Type} - Z4 0x{Z4:X} - Custom Data: {NtObjectUtils.ToHexString(CustomData)} Machine ID: {NtObjectUtils.ToHexString(MachineId)}";
        }

        private protected override byte[] GetBytes()
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            // Length.
            writer.Write(0x30);
            writer.Write(Z4);
            writer.Write(CustomData);
            writer.Write(MachineId);
            return stm.ToArray();
        }
    }
}
