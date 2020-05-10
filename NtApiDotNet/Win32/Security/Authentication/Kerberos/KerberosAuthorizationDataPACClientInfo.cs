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
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent PAC Client Info.
    /// </summary>
    public class KerberosAuthorizationDataPACClientInfo : KerberosAuthorizationDataPACEntry
    {
        /// <summary>
        /// Client ID.
        /// </summary>
        public long ClientId { get; }
        /// <summary>
        /// Name of client.
        /// </summary>
        public string Name { get; }

        private KerberosAuthorizationDataPACClientInfo(KerberosAuthorizationDataPACEntryType type, byte[] data, long client_id, string name)
            : base(type, data)
        {
            ClientId = client_id;
            Name = name;
        }

        internal static bool Parse(KerberosAuthorizationDataPACEntryType type, byte[] data, out KerberosAuthorizationDataPACEntry entry)
        {
            entry = null;
            if (data.Length < 10)
                return false;

            long client_id = BitConverter.ToInt64(data, 0);
            int name_length = BitConverter.ToUInt16(data, 8);
            if (name_length + 10 > data.Length)
                return false;
            string name = Encoding.Unicode.GetString(data, 10, name_length);
            entry = new KerberosAuthorizationDataPACClientInfo(type, data, client_id, name);
            return true;
        }

        private protected override void FormatData(StringBuilder builder)
        {
            try
            {
                builder.AppendLine($"Client ID        : {DateTime.FromFileTime(ClientId)}");
            }
            catch (ArgumentOutOfRangeException)
            {
                builder.AppendLine($"Client ID        : 0x{ClientId:X016}");
            }

            builder.AppendLine($"Client Name      : {Name}");
        }
    }
}
