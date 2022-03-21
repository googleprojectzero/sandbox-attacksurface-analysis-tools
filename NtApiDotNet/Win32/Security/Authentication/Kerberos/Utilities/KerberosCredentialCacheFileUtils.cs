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
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Utilities
{
    internal static class KerberosCredentialCacheFileUtils
    {
        private const int CACHE_FILE_MAGIC = 5;

        private static DateTime BaseUnixTime = new DateTime(1970, 1, 1,
                0, 0, 0, DateTimeKind.Utc);

        public static int ReadFileHeader(this BinaryReader reader)
        {
            if (reader.ReadByte() != CACHE_FILE_MAGIC)
                throw new InvalidDataException("Unsupported cache magic number.");
            return reader.ReadByte();
        }

        public static byte[] ReadData(this BinaryReader reader)
        {
            int length = reader.ReadInt32BE();
            if (length == 0)
                return Array.Empty<byte>();
            return reader.ReadAllBytes(length);
        }

        public static string ReadDataString(this BinaryReader reader)
        {
            return Encoding.UTF8.GetString(ReadData(reader));
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

        public static KerberosAuthenticationKey ReadKeyBlock(this BinaryReader reader)
        {
            KerberosEncryptionType type = (KerberosEncryptionType)reader.ReadUInt16();
            return new KerberosAuthenticationKey(type, ReadData(reader), KerberosNameType.UNKNOWN, string.Empty, DateTime.Now, 0);
        }

        public static KerberosTime ReadUnixTime(this BinaryReader reader)
        {
            int time = reader.ReadInt32BE();
            if (time == 0)
                return null;
            return new KerberosTime(new DateTime(1970, 1, 1,
                0, 0, 0, DateTimeKind.Utc).AddSeconds(time));
        }

        public static KerberosTicket ReadTicket(this BinaryReader reader)
        {
            byte[] data = ReadData(reader);
            if (data.Length == 0)
                return null;
            return KerberosTicket.Parse(data);
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
                    double seconds = new_reader.ReadInt32BE();
                    double microseconds = new_reader.ReadInt32BE();
                    return TimeSpan.FromSeconds(seconds + microseconds / 1000000.0);
                }
                else
                {
                    _ = new_reader.ReadAllBytes(length);
                }
            }
            return new TimeSpan();
        }

        private static int RotateBits(this int value)
        {
            var bits = new BitArray(new int[] { value });
            bits = new BitArray(bits.Cast<bool>().Reverse().ToArray());
            int ret = 0;
            for (int i = 0; i < bits.Length; ++i)
            {
                if (bits[i])
                    ret |= (1 << i);
            }
            return ret;
        }

        public static void ReadCredential(this BinaryReader reader, KerberosCredentialCacheFile file)
        {
            var client = reader.ReadPrincipal();
            var server = reader.ReadPrincipal();
            var key = reader.ReadKeyBlock();
            var auth_time = reader.ReadUnixTime();
            var start_time = reader.ReadUnixTime();
            var end_time = reader.ReadUnixTime();
            var renew_till = reader.ReadUnixTime();
            var is_skey = reader.ReadByte() != 0;
            var ticket_flags = (KerberosTicketFlags)reader.ReadInt32BE().RotateBits();
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
    }
}
