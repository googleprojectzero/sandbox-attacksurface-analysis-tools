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
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// A single kerberos key.
    /// </summary>
    public sealed class KerberosKey
    {
        private readonly byte[] _key;

        /// <summary>
        /// The Key encryption type.
        /// </summary>
        public KRB_ENC_TYPE KeyEncryption { get; }
        /// <summary>
        /// The key.
        /// </summary>
        public byte[] Key => (byte[])_key.Clone();
        /// <summary>
        /// The key name type.
        /// </summary>
        public KRB_NAME_TYPE NameType { get; }
        /// <summary>
        /// The Realm for the key.
        /// </summary>
        public string Realm { get; }
        /// <summary>
        /// The name components for the key.
        /// </summary>
        public IEnumerable<string> Components { get; }
        /// <summary>
        /// Principal name as a string.
        /// </summary>
        public string Principal => $"{string.Join("/", Components)}@{Realm}";
        /// <summary>
        /// Timestamp when key was created.
        /// </summary>
        public DateTime Timestamp { get; }
        /// <summary>
        /// Key Version Number (KVNO).
        /// </summary>
        public uint Version { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="key_encryption">The Key encryption type.</param>
        /// <param name="key">The key.</param>
        /// <param name="name_type">The key name type.</param>
        /// <param name="realm">The Realm for the key.</param>
        /// <param name="components">The name components for the key.</param>
        /// <param name="timestamp">Timestamp when key was created.</param>
        /// <param name="version">Key Version Number (KVNO).</param>
        public KerberosKey(KRB_ENC_TYPE key_encryption, byte[] key, KRB_NAME_TYPE name_type, 
            string realm, string[] components, DateTime timestamp, uint version)
        {
            KeyEncryption = key_encryption;
            _key = key;
            NameType = name_type;
            Realm = realm;
            Components = components;
            Timestamp = timestamp;
            Version = version;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="key_encryption">The Key encryption type.</param>
        /// <param name="key">The key.</param>
        /// <param name="name_type">The key name type.</param>
        /// <param name="realm">The Realm for the key.</param>
        /// <param name="components">The name components for the key.</param>
        /// <param name="timestamp">Timestamp when key was created.</param>
        /// <param name="version">Key Version Number (KVNO).</param>
        public KerberosKey(KRB_ENC_TYPE key_encryption, byte[] key, KRB_NAME_TYPE name_type,
            string realm, IEnumerable<string> components, DateTime timestamp, uint version)
        {
            KeyEncryption = key_encryption;
            _key = (byte[])key.Clone();
            NameType = name_type;
            Realm = realm;
            Components = components.ToArray();
            Timestamp = timestamp;
            Version = version;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="key_encryption">The Key encryption type.</param>
        /// <param name="key">The key.</param>
        /// <param name="name_type">The key name type.</param>
        /// <param name="principal">Principal for key, in form TYPE/name@realm.</param>
        /// <param name="timestamp">Timestamp when key was created.</param>
        /// <param name="version">Key Version Number (KVNO).</param>
        public KerberosKey(KRB_ENC_TYPE key_encryption, byte[] key, KRB_NAME_TYPE name_type,
            string principal, DateTime timestamp, uint version)
            : this(key_encryption, key, name_type, GetRealm(principal),
                  GetComponents(principal), timestamp, version)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="key_encryption">The Key encryption type.</param>
        /// <param name="key">The key as a hex string.</param>
        /// <param name="name_type">The key name type.</param>
        /// <param name="principal">Principal for key, in form TYPE/name@realm.</param>
        /// <param name="timestamp">Timestamp when key was created.</param>
        /// <param name="version">Key Version Number (KVNO).</param>
        public KerberosKey(KRB_ENC_TYPE key_encryption, string key, KRB_NAME_TYPE name_type,
            string principal, DateTime timestamp, uint version)
            : this(key_encryption, GetKey(key), name_type, principal, timestamp, version)
        {
        }

        private static string GetRealm(string principal)
        {
            int index = principal.LastIndexOf('@');
            if (index < 0)
                return string.Empty;
            return principal.Substring(index + 1);
        }

        private static string[] GetComponents(string principal)
        {
            int index = principal.LastIndexOf('@');
            if (index >= 0)
                principal = principal.Substring(0, index);
            return principal.Split('/');
        }

        private static byte[] GetKey(string key)
        {
            if ((key.Length % 1) != 0)
                throw new ArgumentException("Invalid key length.");
            byte[] ret = new byte[key.Length / 2];
            for (int i = 0; i < ret.Length; ++i)
            {
                ret[i] = Convert.ToByte(key.Substring(i * 2, 2), 16);
            }
            return ret;
        }
    }
}
