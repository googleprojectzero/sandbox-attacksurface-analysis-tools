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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    internal static class KerberosUtilsInternal
    {
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
    }
}
