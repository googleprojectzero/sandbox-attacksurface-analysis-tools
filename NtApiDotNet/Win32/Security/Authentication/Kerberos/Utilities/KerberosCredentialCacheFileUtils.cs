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

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Utilities
{
    internal static class KerberosCredentialCacheFileUtils
    {
        private const byte CACHE_FILE_MAGIC = 5;

        private static DateTime BaseUnixTime = new DateTime(1970, 1, 1,
                0, 0, 0, DateTimeKind.Utc);

        public static int ReadFileHeader(this BinaryReader reader)
        {
            if (reader.ReadByte() != CACHE_FILE_MAGIC)
                throw new InvalidDataException("Unsupported cache magic number.");
            return reader.ReadByte();
        }

        public static void WriteFileHeader(this BinaryWriter writer, TimeSpan kdc_offset)
        {
            writer.Write(CACHE_FILE_MAGIC);
            writer.Write((byte)4);
            writer.WriteUInt16BE(12);
            writer.WriteUInt16BE(1);
            writer.WriteUInt16BE(8);
            uint seconds = (uint)kdc_offset.TotalSeconds;
            uint milliseconds = ((uint)(kdc_offset.TotalMilliseconds % 1000.0)) * 1000;
            writer.WriteUInt32BE(seconds);
            writer.WriteUInt32BE(milliseconds);
        }

        public static byte[] ReadData(this BinaryReader reader)
        {
            int length = reader.ReadInt32BE();
            if (length == 0)
                return Array.Empty<byte>();
            return reader.ReadAllBytes(length);
        }

        public static void WriteData(this BinaryWriter writer, byte[] data)
        {
            int length = data?.Length ?? 0;
            writer.WriteInt32BE(length);
            if (length > 0)
                writer.Write(data);
        }

        public static string ReadDataString(this BinaryReader reader)
        {
            return Encoding.UTF8.GetString(ReadData(reader));
        }

        public static void WriteDataString(this BinaryWriter writer, string value)
        {
            WriteData(writer, Encoding.UTF8.GetBytes(value ?? string.Empty));
        }

        public static List<KerberosHostAddress> ReadAddresses(this BinaryReader reader)
        {
            List<KerberosHostAddress> ret = new List<KerberosHostAddress>();
            int count = reader.ReadInt32BE();
            while (count > 0)
            {
                KerberosHostAddressType type = (KerberosHostAddressType)reader.ReadUInt16BE();
                ret.Add(new KerberosHostAddress(type, ReadData(reader)));
                count--;
            }
            return ret;
        }

        public static void WriteAddresses(this BinaryWriter writer, IReadOnlyCollection<KerberosHostAddress> addresses)
        {
            int count = addresses?.Count ?? 0;
            writer.WriteInt32BE(count);
            if (count > 0)
            {
                foreach (var addr in addresses)
                {
                    writer.WriteUInt16BE((int)addr.AddressType);
                    writer.WriteData(addr.Address);
                }
            }
        }

        public static List<KerberosAuthorizationData> ReadAuthData(this BinaryReader reader)
        {
            List<KerberosAuthorizationData> ret = new List<KerberosAuthorizationData>();
            int count = reader.ReadInt32BE();
            while (count > 0)
            {
                KerberosAuthorizationDataType type = (KerberosAuthorizationDataType)reader.ReadUInt16BE();
                ret.Add(new KerberosAuthorizationDataRaw(type, ReadData(reader)));
                count--;
            }
            return ret;
        }

        public static void WriteAuthData(this BinaryWriter writer, IReadOnlyCollection<KerberosAuthorizationData> auth_data)
        {
            int count = auth_data?.Count ?? 0;
            writer.WriteInt32BE(count);
            if (count > 0)
            {
                foreach (var data in auth_data)
                {
                    writer.WriteUInt16BE((int)data.DataType);
                    writer.WriteData(data.ToArray());
                }
            }
        }

        public static KerberosCredentialCacheFilePrincipal ReadPrincipal(this BinaryReader reader)
        {
            KerberosNameType type = (KerberosNameType)reader.ReadInt32BE();
            int count = reader.ReadInt32BE();
            string realm = ReadDataString(reader);
            string[] components = new string[count];
            for (int i = 0; i < count; ++i)
            {
                components[i] = ReadDataString(reader);
            }
            return new KerberosCredentialCacheFilePrincipal(
                new KerberosPrincipalName(type, components), realm);
        }

        public static void WritePrincipal(this BinaryWriter writer, KerberosCredentialCacheFilePrincipal principal)
        {

            writer.WriteInt32BE((int)principal.Name.NameType);
            writer.WriteInt32BE(principal.Name.Names.Count);
            writer.WriteDataString(principal.Realm);
            foreach (string name in principal.Name.Names)
            {
                writer.WriteDataString(name);
            }
        }

        public static KerberosAuthenticationKey ReadKeyBlock(this BinaryReader reader, KerberosCredentialCacheFilePrincipal server)
        {
            KerberosEncryptionType type = (KerberosEncryptionType)reader.ReadUInt16BE();
            return new KerberosAuthenticationKey(type, ReadData(reader), server.Name.NameType, server.Name.GetPrincipal(server.Realm), DateTime.Now, 0);
        }

        public static void WriteKeyBlock(this BinaryWriter writer, KerberosAuthenticationKey key)
        {
            if (key == null)
            {
                writer.WriteUInt16BE((int)KerberosEncryptionType.NULL);
                writer.WriteData(null);
            }
            else
            {
                writer.WriteUInt16BE((int)key.KeyEncryption);
                writer.WriteData(key.Key);
            }
        }

        public static KerberosTime ReadUnixTime(this BinaryReader reader)
        {
            uint time = reader.ReadUInt32BE();
            if (time == 0)
                return null;
            return new KerberosTime(new DateTime(1970, 1, 1,
                0, 0, 0, DateTimeKind.Utc).AddSeconds(time));
        }

        public static void WriteUnixTime(this BinaryWriter writer, KerberosTime time)
        {
            var curr = time?.ToDateTime().Subtract(new DateTime(1970, 1, 1,
                0, 0, 0, DateTimeKind.Utc)).TotalSeconds ?? 0;
            if (curr < 0 || curr > uint.MaxValue)
                curr = 0;
            writer.WriteUInt32BE((uint)curr);
        }

        public static KerberosTicket ReadTicket(this BinaryReader reader)
        {
            byte[] data = ReadData(reader);
            if (data.Length == 0)
                return null;
            return KerberosTicket.Parse(data);
        }

        public static void WriteTicket(this BinaryWriter writer, KerberosTicket ticket)
        {
            writer.WriteData(ticket?.ToArray());
        }

        public static TimeSpan ReadKDCOffset(this BinaryReader reader)
        {
            int header_length = reader.ReadUInt16BE();
            MemoryStream stm = new MemoryStream(reader.ReadAllBytes(header_length));
            BinaryReader new_reader = new BinaryReader(stm);
            while (stm.Position < header_length)
            {
                int tag = new_reader.ReadUInt16BE();
                int length = new_reader.ReadUInt16BE();
                if (tag == 1 && length == 8)
                {
                    double seconds = new_reader.ReadUInt32BE();
                    double microseconds = new_reader.ReadUInt32BE();
                    return TimeSpan.FromSeconds(seconds).Add(TimeSpan.FromMilliseconds(microseconds / 1000.0));
                }
                else
                {
                    _ = new_reader.ReadAllBytes(length);
                }
            }
            return new TimeSpan();
        }

        public static void ReadCredential(this BinaryReader reader, KerberosCredentialCacheFile file)
        {
            var client = reader.ReadPrincipal();
            var server = reader.ReadPrincipal();
            var key = reader.ReadKeyBlock(server);
            var auth_time = reader.ReadUnixTime();
            var start_time = reader.ReadUnixTime();
            var end_time = reader.ReadUnixTime();
            var renew_till = reader.ReadUnixTime();
            var is_skey = reader.ReadByte() != 0;
            var ticket_flags = (KerberosTicketFlags)reader.ReadUInt32BE().RotateBits();
            var addresses = reader.ReadAddresses();
            var auth_data = reader.ReadAuthData();

            if (server.IsConfigEntry)
            {
                var data = reader.ReadData();
                _ = reader.ReadData();
                file.Configuration.Add(new KerberosCredentialCacheFileConfigEntry(server.Name.Names[1], data,
                    server.Name.Names.Count > 2 ? server.Name.Names[2] : string.Empty));
            }
            else
            {
                var ticket = reader.ReadTicket();
                var second_ticket = reader.ReadTicket();
                file.Credentials.Add(new KerberosCredentialCacheFileCredential(client, server, key, auth_time,
                    start_time, end_time, renew_till, is_skey, ticket_flags, addresses, auth_data,
                    ticket, second_ticket));
            }
        }

        public static KerberosTime ToKerbTime(this DateTime time)
        {
            if (time == DateTime.MinValue)
                return null;
            return new KerberosTime(time);
        }
    }
}
