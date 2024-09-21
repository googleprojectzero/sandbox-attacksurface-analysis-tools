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

using System.Collections.Generic;
using System.IO;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Utilities
{
    /// <summary>
    /// Configuration entry.
    /// </summary>
    public sealed class KerberosCredentialCacheFileConfigEntry
    {
        /// <summary>
        /// The configuaration key.
        /// </summary>
        public string Key { get; }

        /// <summary>
        /// Optional principal for the config entry.
        /// </summary>
        public string Principal { get; }

        /// <summary>
        /// The configuration data.
        /// </summary>
        public byte[] Data { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data">The configuration data.</param>
        /// <param name="principal"></param>
        public KerberosCredentialCacheFileConfigEntry(string key, byte[] data, string principal)
        {
            Key = key ?? throw new System.ArgumentNullException(nameof(key));
            Data = data ?? throw new System.ArgumentNullException(nameof(data));
            Principal = principal;
        }

        internal void Write(BinaryWriter writer, KerberosCredentialCacheFilePrincipal default_principal)
        {
            List<string> parts = new List<string>()
            {
                "krb5_ccache_conf_data",
                Key
            };
            if (!string.IsNullOrEmpty(Principal))
            {
                parts.Add(Principal);
            }
            var server = new KerberosCredentialCacheFilePrincipal(new KerberosPrincipalName(KerberosNameType.UNKNOWN, parts), "X-CACHECONF:");

            writer.WritePrincipal(default_principal);
            writer.WritePrincipal(server);
            writer.WriteKeyBlock(null);
            writer.WriteUnixTime(null);
            writer.WriteUnixTime(null);
            writer.WriteUnixTime(null);
            writer.WriteUnixTime(null);
            writer.Write((byte)0);
            writer.Write(0);
            writer.WriteAddresses(null);
            writer.WriteAuthData(null);
            writer.WriteData(Data);
            writer.WriteData(null);
        }
    }
}
