//  Copyright 2021 Google LLC. All Rights Reserved.
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

using NtApiDotNet.Utilities.ASN1.Builder;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder
{
    /// <summary>
    /// Utilities for building Kerberos structures.
    /// </summary>
    internal static class KerberosBuilderUtils
    {
        internal static void WriteKerberosHeader(this DERBuilder builder, KerberosMessageType msg_type)
        {
            builder.WriteContextSpecific(0, 5);
            builder.WriteContextSpecific(1, (int)msg_type);
        }

        internal static DERBuilderSubStructure CreateMsg(this DERBuilder builder, KerberosMessageType type)
        {
            return builder.CreateApplication((int)type);
        }

        internal static byte[] CreateGssApiWrapper(this DERBuilder inner_token, string oid, ushort token_id)
        {
            return CreateGssApiWrapper(inner_token.ToArray(), oid, token_id);
        }

        internal static byte[] CreateGssApiWrapper(byte[] inner_token, string oid, ushort token_id)
        {
            var builder = new DERBuilder();
            using (var app = builder.CreateApplication(0))
            {
                app.WriteObjectId(oid);
                byte[] ba = BitConverter.GetBytes(token_id);
                Array.Reverse(ba);
                app.WriteRawBytes(ba);
                app.WriteRawBytes(inner_token);
            }
            return builder.ToArray();
        }

        internal static int GetRandomNonce()
        {
            return new Random().Next();
        }

        public static IEnumerable<KerberosAuthorizationDataBuilder> FindAuthorizationDataBuilder(this IEnumerable<KerberosAuthorizationDataBuilder> list, KerberosAuthorizationDataType data_type)
        {
            List<KerberosAuthorizationDataBuilder> ret = new List<KerberosAuthorizationDataBuilder>();
            list.FindBuildersInList(ret, data_type, null);
            return ret.AsReadOnly();
        }

        public static IEnumerable<T> FindAuthorizationDataBuilder<T>(this IEnumerable<KerberosAuthorizationDataBuilder> list) where T : KerberosAuthorizationDataBuilder
        {
            List<KerberosAuthorizationDataBuilder> ret = new List<KerberosAuthorizationDataBuilder>();
            list.FindBuildersInList(ret, KerberosAuthorizationDataType.UNKNOWN, typeof(T));
            return ret.OfType<T>().ToList();
        }

        private static void FindBuildersInList(
                this IEnumerable<KerberosAuthorizationDataBuilder> list, List<KerberosAuthorizationDataBuilder> ret,
                KerberosAuthorizationDataType data_type, Type type)
        {
            if (list == null)
                return;
            foreach (var entry in list)
            {
                if (entry.DataType == data_type || entry.GetType() == type)
                    ret.Add(entry);
                if (entry is KerberosAuthorizationDataIfRelevantBuilder if_relevant)
                {
                    if_relevant.Entries.FindBuildersInList(ret, data_type, type);
                }
            }
        }
    }
}
