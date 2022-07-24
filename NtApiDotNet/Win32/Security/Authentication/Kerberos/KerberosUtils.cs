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
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Utilities for Kerberos authentication.
    /// </summary>
    public static class KerberosUtils
    {
        private static KerberosAuthenticationKey Parse(byte[] data)
        {
            BinaryReader reader = new BinaryReader(new MemoryStream(data));
            int count = ReadUInt16(reader);
            string realm = ReadString(reader);
            string[] components = Enumerable.Range(0, count).Select(i => ReadString(reader)).ToArray();
            int name_type = ReadInt32(reader);
            uint timestamp = ReadUInt32(reader);
            uint version = reader.ReadByte();
            int key_type = ReadInt16(reader);
            byte[] key = ReadOctets(reader);
            if (reader.BaseStream.Position <= reader.BaseStream.Length - 4)
            {
                version = ReadUInt32(reader);
            }
            return new KerberosAuthenticationKey((KerberosEncryptionType)key_type, key, (KerberosNameType)name_type, 
                realm, components, new DateTime(1970, 1, 1).AddSeconds(timestamp), version);
        }

        private static byte[] SerializeEntry(KerberosAuthenticationKey entry)
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            WriteUInt16(writer, (ushort)entry.Components.Count());
            WriteString(writer, entry.Realm);
            foreach (string s in entry.Components)
            {
                WriteString(writer, s);
            }
            WriteInt32(writer, (int)entry.NameType);
            WriteUInt32(writer, (uint)entry.Timestamp.Subtract(new DateTime(1970, 1, 1)).TotalSeconds);
            writer.Write((byte)entry.Version);
            WriteUInt16(writer, (ushort)entry.KeyEncryption);
            WriteOctets(writer, entry.Key);
            WriteUInt32(writer, entry.Version);
            return stm.ToArray();
        }

        private static void WriteInt32(BinaryWriter writer, int value)
        {
            byte[] ba = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
                ba = ba.Reverse().ToArray();
            writer.Write(ba);
        }

        private static void WriteUInt32(BinaryWriter writer, uint value)
        {
            byte[] ba = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
                ba = ba.Reverse().ToArray();
            writer.Write(ba);
        }

        private static void WriteUInt16(BinaryWriter writer, ushort value)
        {
            byte[] ba = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
                ba = ba.Reverse().ToArray();
            writer.Write(ba);
        }

        private static void WriteOctets(BinaryWriter writer, byte[] data)
        {
            WriteUInt16(writer, (ushort)data.Length);
            writer.Write(data);
        }

        private static void WriteString(BinaryWriter writer, string str)
        {
            WriteOctets(writer, Encoding.UTF8.GetBytes(str));
        }

        private static int ReadInt32(BinaryReader reader)
        {
            int value = reader.ReadInt32();
            if (BitConverter.IsLittleEndian)
            {
                value = BitConverter.ToInt32(BitConverter.GetBytes(value).Reverse().ToArray(), 0);
            }
            return value;
        }

        private static uint ReadUInt32(BinaryReader reader)
        {
            uint value = reader.ReadUInt32();
            if (BitConverter.IsLittleEndian)
            {
                value = BitConverter.ToUInt32(BitConverter.GetBytes(value).Reverse().ToArray(), 0);
            }
            return value;
        }

        private static ushort ReadUInt16(BinaryReader reader)
        {
            ushort value = reader.ReadUInt16();
            if (BitConverter.IsLittleEndian)
            {
                value = BitConverter.ToUInt16(BitConverter.GetBytes(value).Reverse().ToArray(), 0);
            }
            return value;
        }

        private static short ReadInt16(BinaryReader reader)
        {
            short value = reader.ReadInt16();
            if (BitConverter.IsLittleEndian)
            {
                value = BitConverter.ToInt16(BitConverter.GetBytes(value).Reverse().ToArray(), 0);
            }
            return value;
        }

        private static byte[] ReadOctets(BinaryReader reader)
        {
            int length = ReadUInt16(reader);
            byte[] ret = reader.ReadBytes(length);
            if (ret.Length != length)
                throw new EndOfStreamException();
            return ret;
        }

        private static string ReadString(BinaryReader reader)
        {
            return Encoding.UTF8.GetString(ReadOctets(reader));
        }

        internal static uint RotateBits(this uint value)
        {
            uint ret = 0;
            for (int i = 0; i < 32; ++i)
            {
                if ((value & (1U << i)) != 0)
                {
                    ret |= (0x80000000U >> i);
                }
            }
            return ret;
        }

        internal static ushort SwapEndian(this ushort value)
        {
            return BitConverter.ToUInt16(BitConverter.GetBytes(value).Reverse().ToArray(), 0);
        }

        internal static int SwapEndian(this int value)
        {
            return BitConverter.ToInt32(BitConverter.GetBytes(value).Reverse().ToArray(), 0);
        }

        internal static uint SwapEndian(this uint value)
        {
            return BitConverter.ToUInt32(BitConverter.GetBytes(value).Reverse().ToArray(), 0);
        }

        internal static long SwapEndian(this long value)
        {
            return BitConverter.ToInt64(BitConverter.GetBytes(value).Reverse().ToArray(), 0);
        }

        internal static ushort ReadUInt16BE(this BinaryReader reader)
        {
            return reader.ReadUInt16().SwapEndian();
        }

        internal static void WriteInt32BE(this BinaryWriter writer, int value)
        {
            writer.Write(value.SwapEndian());
        }

        internal static void WriteUInt32BE(this BinaryWriter writer, uint value)
        {
            writer.Write(value.SwapEndian());
        }

        internal static void WriteUInt16BE(this BinaryWriter writer, int value)
        {
            writer.Write(((ushort)value).SwapEndian());
        }

        internal static int ReadInt32BE(this BinaryReader reader)
        {
            return reader.ReadInt32().SwapEndian();
        }

        internal static uint ReadUInt32BE(this BinaryReader reader)
        {
            return reader.ReadUInt32().SwapEndian();
        }

        internal static bool CheckMsg(this DERValue value, KerberosMessageType msg)
        {
            return value.CheckApplication((int)msg);
        }

        internal static KerberosTime ReadChildKerberosTime(this DERValue value)
        {
            return new KerberosTime(value.ReadChildGeneralizedTime());
        }

        internal static KerberosPrincipalName ReadChildPrincipalName(this DERValue value)
        {
            if (!value.HasChildren() || !value.Children[0].CheckSequence())
            {
                throw new InvalidDataException();
            }
            return KerberosPrincipalName.Parse(value.Children[0]);
        }

        internal static KerberosAuthenticationKey ReadChildAuthenticationKey(this DERValue value)
        {
            if (!value.HasChildren() || !value.Children[0].CheckSequence())
            {
                throw new InvalidDataException();
            }
            return KerberosAuthenticationKey.Parse(value.Children[0], string.Empty, new KerberosPrincipalName());
        }

        internal static KerberosEncryptedData ReadChildEncryptedData(this DERValue value)
        {
            if (!value.HasChildren())
                throw new InvalidDataException();
            return KerberosEncryptedData.Parse(value.Children[0], value.Data);
        }

        internal static KerberosTicket ReadChildTicket(this DERValue value)
        {
            if (!value.HasChildren())
                throw new InvalidDataException();
            return KerberosTicket.Parse(value.Children[0]);
        }

        internal static IEnumerable<T> FindAllAuthorizationData<T>(
            this IEnumerable<KerberosAuthorizationData> auth_data,
            KerberosAuthorizationDataType type) where T : KerberosAuthorizationData
        {
            if (auth_data == null)
                return default;
            List<KerberosAuthorizationData> list = new List<KerberosAuthorizationData>();
            FindAuthorizationData(list, auth_data, type);
            return list.OfType<T>();
        }

        internal static T FindAuthorizationData<T>(
            this IEnumerable<KerberosAuthorizationData> auth_data,
            KerberosAuthorizationDataType type) where T : KerberosAuthorizationData
        {
            return auth_data.FindAllAuthorizationData<T>(type).FirstOrDefault();
        }

        private static void FindAuthorizationData(
            List<KerberosAuthorizationData> list,
            IEnumerable<KerberosAuthorizationData> auth_data,
            KerberosAuthorizationDataType type)
        {
            if (auth_data == null)
                return;
            foreach (var next in auth_data)
            {
                if (next.DataType == type)
                    list.Add(next);
                if (next is KerberosAuthorizationDataIfRelevant if_rel)
                {
                    FindAuthorizationData(list, if_rel.Entries, type);
                }
            }
            return;
        }

        /// <summary>
        /// Read keys from a MIT KeyTab file.
        /// </summary>
        /// <param name="stream">The file stream.</param>
        /// <returns>The list of keys.</returns>
        /// <exception cref="ArgumentException">Throw if invalid file.</exception>
        public static IEnumerable<KerberosAuthenticationKey> ReadKeyTabFile(Stream stream)
        {
            using (var reader = new BinaryReader(stream))
            {
                byte id = reader.ReadByte();
                if (id != 5)
                    throw new ArgumentException("Invalid KeyTab file, file byte is not 5");
                byte type = reader.ReadByte();
                if (type != 2)
                    throw new ArgumentException("Invalid KeyTab file, only support version 2.");

                List<KerberosAuthenticationKey> entries = new List<KerberosAuthenticationKey>();
                while (reader.BaseStream.Position < reader.BaseStream.Length)
                {
                    int size = ReadInt32(reader);
                    if (size == 0)
                        break;
                    byte[] data = reader.ReadBytes(Math.Abs(size));
                    if (data.Length != Math.Abs(size))
                    {
                        throw new EndOfStreamException();
                    }
                    if (size > 0)
                    {
                        entries.Add(Parse(data));
                    }
                }
                return entries.AsReadOnly();
            }
        }

        /// <summary>
        /// Read keys from a MIT KeyTab file.
        /// </summary>
        /// <param name="path">The file path.</param>
        /// <returns>The list of keys.</returns>
        /// <exception cref="ArgumentException">Throw if invalid file.</exception>
        public static IEnumerable<KerberosAuthenticationKey> ReadKeyTabFile(string path)
        {
            using (var stream = File.OpenRead(path))
            {
                return ReadKeyTabFile(stream);
            }
        }

        /// <summary>
        /// Write keys to a MIT KeyTab file.
        /// </summary>
        /// <param name="stream">The file stream.</param>
        /// <param name="keys">List of key entries.</param>
        public static void WriteKeyTabFile(Stream stream, IEnumerable<KerberosAuthenticationKey> keys)
        {
            using (var writer = new BinaryWriter(stream))
            {
                writer.Write((byte)5);
                writer.Write((byte)2);
                foreach (var entry in keys)
                {
                    byte[] data = SerializeEntry(entry);
                    WriteInt32(writer, data.Length);
                    writer.Write(data);
                }
            }
        }

        /// <summary>
        /// Write keys to a MIT KeyTab file.
        /// </summary>
        /// <param name="path">The file path.</param>
        /// <param name="keys">List of key entries.</param>
        public static void WriteKeyTabFile(string path, IEnumerable<KerberosAuthenticationKey> keys)
        {
            using (var stream = File.OpenWrite(path))
            {
                WriteKeyTabFile(stream, keys);
            }
        }

        /// <summary>
        /// Generate an MIT KeyTab file.
        /// </summary>
        /// <param name="keys">List of key entries.</param>
        /// <returns>The keytab file as bytes.</returns>
        public static byte[] GenerateKeyTabFile(IEnumerable<KerberosAuthenticationKey> keys)
        {
            MemoryStream stm = new MemoryStream();
            WriteKeyTabFile(stm, keys);
            return stm.ToArray();
        }
    }
}
