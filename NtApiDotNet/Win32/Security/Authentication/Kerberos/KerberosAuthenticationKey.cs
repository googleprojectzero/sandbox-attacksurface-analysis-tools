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
using NtApiDotNet.Utilities.ASN1.Builder;
using NtApiDotNet.Win32.Security.Authentication.Kerberos.Cryptography;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// A single kerberos key.
    /// </summary>
    public sealed class KerberosAuthenticationKey : AuthenticationKey, IDERObject
    {
        #region Public Properties
        /// <summary>
        /// The Key encryption type.
        /// </summary>
        public KerberosEncryptionType KeyEncryption => _enc_engine.EncryptionType;

        /// <summary>
        /// The key.
        /// </summary>
        public byte[] Key => (byte[])_key.Clone();

        /// <summary>
        /// The key name type.
        /// </summary>
        public KerberosNameType NameType => Name.NameType;

        /// <summary>
        /// The Realm for the key.
        /// </summary>
        public string Realm { get; }

        /// <summary>
        /// The name components for the key.
        /// </summary>
        public IEnumerable<string> Components => Name.Names;

        /// <summary>
        /// Principal name as a string.
        /// </summary>
        public string Principal => Name.GetPrincipal(Realm);

        /// <summary>
        /// Timestamp when key was created.
        /// </summary>
        public DateTime Timestamp { get; }

        /// <summary>
        /// Key Version Number (KVNO).
        /// </summary>
        public uint Version { get; }

        /// <summary>
        /// Size of the checksum.
        /// </summary>
        public int ChecksumSize => _enc_engine.ChecksumSize;

        /// <summary>
        /// Size of any additional encryption artifacts.
        /// </summary>
        public int AdditionalEncryptionSize => _enc_engine.AdditionalEncryptionSize;

        /// <summary>
        /// Returns whether the key is all zeros typically indicating it's invalid.
        /// </summary>
        public bool IsZeroKey => NtObjectUtils.EqualByteArray(Key, new byte[Key.Length]);

        /// <summary>
        /// Get the checksum type associated with the key algorithm.
        /// </summary>
        public KerberosChecksumType ChecksumType => _enc_engine.ChecksumType;

        /// <summary>
        /// The kerberos principal name.
        /// </summary>
        public KerberosPrincipalName Name { get; }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="key_encryption">The Key encryption type.</param>
        /// <param name="key">The key.</param>
        /// <param name="realm">The Realm for the key.</param>
        /// <param name="name">The principal name for the key.</param>
        /// <param name="timestamp">Timestamp when key was created.</param>
        /// <param name="version">Key Version Number (KVNO).</param>
        public KerberosAuthenticationKey(KerberosEncryptionType key_encryption, byte[] key,
            string realm, KerberosPrincipalName name, DateTime timestamp, uint version)
        {
            _enc_engine = KerberosEncryptionEngine.Get(key_encryption, false);
            _chk_engine = KerberosChecksumEngine.Get(_enc_engine.ChecksumType, false);
            _key = key;
            Name = name;
            Realm = realm;
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
            string realm, string[] components, DateTime timestamp, uint version) : this(key_encryption, 
                key, realm, new KerberosPrincipalName(name_type, components), timestamp, version)
        {
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
            string realm, IEnumerable<string> components, DateTime timestamp, uint version) : this(key_encryption,
                key, name_type, realm, components.ToArray(), timestamp, version)
        {
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
        #endregion

        #region Static Methods
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
        /// <returns>The derived key.</returns>
        public static KerberosAuthenticationKey DeriveKey(KerberosEncryptionType key_encryption, string password, 
            int iterations, KerberosNameType name_type, string principal, string salt, uint version)
        {
            if (principal is null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            KerberosEncryptionEngine enc_engine = KerberosEncryptionEngine.Get(key_encryption, false);
            byte[] key = enc_engine.DeriveKey(password, iterations, MakeSalt(salt, principal));
            return new KerberosAuthenticationKey(key_encryption, key, name_type, principal, DateTime.Now, version);
        }

        /// <summary>
        /// Generate a random key.
        /// </summary>
        /// <param name="key_encryption">The encryption type for the key.</param>
        /// <returns>The generated key.</returns>
        public static KerberosAuthenticationKey GenerateKey(KerberosEncryptionType key_encryption)
        {
            KerberosEncryptionEngine enc_engine = KerberosEncryptionEngine.Get(key_encryption, false);
            byte[] key = enc_engine.GenerateKey();
            return new KerberosAuthenticationKey(key_encryption, key, KerberosNameType.UNKNOWN, string.Empty, DateTime.Now, 0);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Try and decrypt an encrypted cipher text.
        /// </summary>
        /// <param name="key_usage">The key usage for the decryption.</param>
        /// <param name="plain_text">The plain text.</param>
        /// <param name="cipher_text">The cipher text.</param>
        /// <returns>True if successfully decrypted.</returns>
        public bool TryDecrypt(byte[] cipher_text, KerberosKeyUsage key_usage, out byte[] plain_text)
        {
            return _enc_engine.TryDecrypt(_key, cipher_text, key_usage, out plain_text);
        }

        /// <summary>
        /// Decrypt an encrypted cipher text.
        /// </summary>
        /// <param name="key_usage">The key usage for the decryption.</param>
        /// <param name="cipher_text">The cipher text.</param>
        /// <returns>The decrypted data.</returns>
        /// <exception cref="InvalidDataException">Thrown if can't decrypt.</exception>
        public byte[] Decrypt(byte[] cipher_text, KerberosKeyUsage key_usage)
        {
            return _enc_engine.Decrypt(_key, cipher_text, key_usage);
        }

        /// <summary>
        /// Encrypt a plain text buffer.
        /// </summary>
        /// <param name="plain_text">The plain text to encrypt.</param>
        /// <param name="key_usage">The Kerberos key usage.</param>
        /// <returns>The encrypted buffer.</returns>
        /// <exception cref="InvalidDataException">Thrown in can't encrypt.</exception>
        public byte[] Encrypt(byte[] plain_text, KerberosKeyUsage key_usage)
        {
            return _enc_engine.Encrypt(_key, plain_text, key_usage);
        }

        /// <summary>
        /// Compute a hash for a set of data.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <param name="offset">Offset into the data to hash.</param>
        /// <param name="length">The length of the data to hash.</param>
        /// <param name="key_usage">The key usage.</param>
        /// <returns>The computed hash.</returns>
        public byte[] ComputeHash(byte[] data, int offset, int length, KerberosKeyUsage key_usage)
        {
            return _chk_engine.ComputeHash(_key, data, offset, length, key_usage);
        }

        /// <summary>
        /// Compute a hash for a set of data.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <param name="key_usage">The key usage.</param>
        /// <returns>The computed hash.</returns>
        public byte[] ComputeHash(byte[] data, KerberosKeyUsage key_usage)
        {
            return ComputeHash(data, 0, data.Length, key_usage);
        }

        /// <summary>
        /// Verify a hash.
        /// </summary>
        /// <param name="hash">The hash to verify.</param>
        /// <param name="data">The data to hash.</param>
        /// <param name="offset">Offset into the data to hash.</param>
        /// <param name="length">The length of the data to hash.</param>
        /// <param name="key_usage">The key usage.</param>
        /// <returns>True if the hash matches.</returns>
        public bool VerifyHash(byte[] hash, byte[] data, int offset, int length, KerberosKeyUsage key_usage)
        {
            return NtObjectUtils.EqualByteArray(hash, ComputeHash(data, offset, length, key_usage));
        }

        /// <summary>
        /// Verify a hash.
        /// </summary>
        /// <param name="hash">The hash to verify.</param>
        /// <param name="data">The data to hash.</param>
        /// <param name="key_usage">The key usage.</param>
        /// <returns>True if the hash matches.</returns>
        public bool VerifyHash(byte[] hash, byte[] data, KerberosKeyUsage key_usage)
        {
            return VerifyHash(hash, data, 0, data.Length, key_usage);
        }

        /// <summary>
        /// Generate a random key based on this key's encryption type.
        /// </summary>
        /// <returns>The generated key.</returns>
        public KerberosAuthenticationKey GenerateKey()
        {
            return GenerateKey(KeyEncryption);
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The formatting string.</returns>
        public override string ToString()
        {
            return $"{KeyEncryption} {Convert.ToBase64String(Key)}";
        }

        #endregion

        #region Internal Members
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

        internal KerberosAuthenticationKey CloneWithName(KerberosPrincipalName name, string realm)
        {
            return new KerberosAuthenticationKey(KeyEncryption, (byte[])_key.Clone(), realm, name, DateTime.Now, Version); 
        }

        void IDERObject.Write(DERBuilder builder)
        {
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, (int)KeyEncryption);
                seq.WriteContextSpecific(1, Key);
            }
        }
        #endregion

        #region Private Members
        private readonly byte[] _key;
        private readonly KerberosEncryptionEngine _enc_engine;
        private readonly KerberosChecksumEngine _chk_engine;

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
        #endregion
    }
}
