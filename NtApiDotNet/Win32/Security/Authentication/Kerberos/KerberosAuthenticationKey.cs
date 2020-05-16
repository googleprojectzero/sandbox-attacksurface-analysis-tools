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
using NtApiDotNet.Utilities.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// A single kerberos key.
    /// </summary>
    public sealed class KerberosAuthenticationKey : AuthenticationKey
    {
        private readonly byte[] _key;

        /// <summary>
        /// The Key encryption type.
        /// </summary>
        public KerberosEncryptionType KeyEncryption { get; }
        /// <summary>
        /// The key.
        /// </summary>
        public byte[] Key => (byte[])_key.Clone();
        /// <summary>
        /// The key name type.
        /// </summary>
        public KerberosNameType NameType { get; }
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
        public KerberosAuthenticationKey(KerberosEncryptionType key_encryption, byte[] key, KerberosNameType name_type, 
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
        public KerberosAuthenticationKey(KerberosEncryptionType key_encryption, byte[] key, KerberosNameType name_type,
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
        public KerberosAuthenticationKey(KerberosEncryptionType key_encryption, byte[] key, KerberosNameType name_type,
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
        public KerberosAuthenticationKey(KerberosEncryptionType key_encryption, string key, KerberosNameType name_type,
            string principal, DateTime timestamp, uint version)
            : this(key_encryption, GetKey(key), name_type, principal, timestamp, version)
        {
        }

        /// <summary>
        /// Derive a key from a password.
        /// </summary>
        /// <remarks>Not all encryption types are supported.</remarks>
        /// <param name="key_encryption">The key encryption to use.</param>
        /// <param name="password">The password to derice from.</param>
        /// <param name="iterations">Iterations for the password derivation.</param>
        /// <param name="name_type">The key name type.</param>
        /// <param name="principal">Principal for key, in form TYPE/name@realm.</param>
        /// <param name="salt">Salt for the key.</param>
        /// <param name="version">Key Version Number (KVNO).</param>
        /// <returns></returns>
        public static KerberosAuthenticationKey DeriveKey(KerberosEncryptionType key_encryption, string password, 
            int iterations, KerberosNameType name_type, string principal, string salt, uint version)
        {
            if (principal is null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            byte[] key;

            switch (key_encryption)
            {
                case KerberosEncryptionType.ARCFOUR_HMAC_MD5:
                case KerberosEncryptionType.ARCFOUR_HMAC_MD5_56:
                case KerberosEncryptionType.ARCFOUR_HMAC_OLD:
                case KerberosEncryptionType.ARCFOUR_HMAC_OLD_EXP:
                    key = MD4.CalculateHash(Encoding.Unicode.GetBytes(password));
                    break;
                case KerberosEncryptionType.AES128_CTS_HMAC_SHA1_96:
                    key = DeriveAesKey(password, MakeSalt(salt, principal), iterations, 16);
                    break;
                case KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96:
                    key = DeriveAesKey(password, MakeSalt(salt, principal), iterations, 32);
                    break;
                default:
                    throw new ArgumentException($"Unsupported key type {key_encryption}", nameof(key_encryption));
            }

            return new KerberosAuthenticationKey(key_encryption, key, name_type, principal, DateTime.Now, version);
        }

        internal static KerberosAuthenticationKey Parse(DERValue value, string realm, KerberosPrincipalName name)
        {
            if (!value.CheckSequence())
                throw new InvalidDataException();
            KerberosEncryptionType enc_type = 0;
            byte[] key = null;
            foreach (var next in value.Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    throw new InvalidDataException();
                switch (next.Tag)
                {
                    case 0:
                        enc_type = (KerberosEncryptionType)next.ReadChildInteger();
                        break;
                    case 1:
                        key = next.ReadChildOctetString();
                        break;
                    default:
                        throw new InvalidDataException();
                }
            }

            if (enc_type == 0 || key == null)
                throw new InvalidDataException();
            return new KerberosAuthenticationKey(enc_type, key, name.NameType, realm, name.Names.ToArray(), DateTime.Now, 0);
        }

        private static string MakeSalt(string salt, string principal)
        {
            if (!string.IsNullOrEmpty(salt))
                return salt;
            return GetRealm(principal).ToUpper() + string.Join("", GetComponents(principal));
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


        private static byte[] DeriveAesKey(string password, string salt, int iterations, int key_size)
        {
            Rfc2898DeriveBytes pbkdf = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(password), Encoding.UTF8.GetBytes(salt), iterations);
            return DeriveAesKey(pbkdf.GetBytes(key_size), NFold.Compute("kerberos", 16));
        }

        internal static byte[] DeriveAesKey(byte[] base_key, byte[] folded_key)
        {
            Aes encrypt = new AesManaged();
            encrypt.Mode = CipherMode.ECB;

            folded_key = (byte[])folded_key.Clone();

            byte[] ret = new byte[base_key.Length];
            var transform = encrypt.CreateEncryptor(base_key, new byte[16]);
            transform.TransformBlock(folded_key, 0, 16, folded_key, 0);
            Array.Copy(folded_key, ret, 16);
            if (ret.Length > 16)
            {
                transform.TransformBlock(folded_key, 0, 16, folded_key, 0);
                Array.Copy(folded_key, 0, ret, 16, 16);
            }
            return ret;
        }
    }
}
