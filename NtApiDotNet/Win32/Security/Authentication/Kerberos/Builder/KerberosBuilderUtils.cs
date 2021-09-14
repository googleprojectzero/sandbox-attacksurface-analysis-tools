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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder
{
    internal static class KerberosBuilderUtils
    {
        public static void WriteKerberosHeader(this DERBuilder builder, KerberosMessageType msg_type)
        {
            builder.WriteContextSpecific(0, b => b.WriteInt32(5));
            builder.WriteContextSpecific(1, b => b.WriteInt32((int)msg_type));
        }

        public static void WritePrincipalName(this DERBuilder builder, KerberosPrincipalName name)
        {
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, b => b.WriteInt32((int)name.NameType));
                seq.WriteContextSpecific(1, b => b.WriteSequence(name.Names, 
                    (s, v) => s.WriteGeneralString(v)));
            }
        }

        public static void WriteKerberosTime(this DERBuilder builder, int context, DateTime time)
        {
            builder.WriteContextSpecific(context, b => b.WriteGeneralizedTime(time));
            builder.WriteContextSpecific(context + 1, b => b.WriteInt32(time.Millisecond * 1000));
        }

        public static byte[] CreateGssApiWrapper(this DERBuilder inner_token, string oid, ushort token_id)
        {
            return CreateGssApiWrapper(inner_token.ToArray(), oid, token_id);
        }

        public static byte[] CreateGssApiWrapper(byte[] inner_token, string oid, ushort token_id)
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
    }
}
