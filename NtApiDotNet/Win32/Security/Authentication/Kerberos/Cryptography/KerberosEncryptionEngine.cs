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
using System.Linq;
using System.Security.Cryptography;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Cryptography
{
    /// <summary>
    /// Base class for a Kerberos encryption engine.
    /// </summary>
    public abstract class KerberosEncryptionEngine
    {
        #region Private Members
        private static Dictionary<KerberosEncryptionType, KerberosEncryptionEngine> _engines;

        private static KerberosEncryptionEngine AddEngine(KerberosEncryptionEngine engine)
        {
            _engines.Add(engine.EncryptionType, engine);
            return engine;
        }

        private static void InitDefaultEngines()
        {
            if (_engines != null)
                return;
            _engines = new Dictionary<KerberosEncryptionType, KerberosEncryptionEngine>();
            AddEngine(KerberosEncryptionEngineAESSHA196.AES128);
            AddEngine(KerberosEncryptionEngineAESSHA196.AES256);
            AddEngine(new KerberosEncryptionEngineARC4MD5());
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Encrypt a buffer.
        /// </summary>
        /// <param name="key">The encryption key.</param>
        /// <param name="plain_text">The plain text to encrypt.</param>
        /// <param name="key_usage">The key usage.</param>
        /// <returns>The encrypted data.</returns>
        public abstract byte[] Encrypt(byte[] key, byte[] plain_text, KerberosKeyUsage key_usage);

        /// <summary>
        /// Try and decrypt an encrypted cipher text.
        /// </summary>
        /// <param name="key">The encryption key.</param>
        /// <param name="key_usage">The key usage for the decryption.</param>
        /// <param name="plain_text">The plain text.</param>
        /// <param name="cipher_text">The cipher text.</param>
        /// <returns>True if successfully decrypted.</returns>
        public abstract bool TryDecrypt(byte[] key, byte[] cipher_text, KerberosKeyUsage key_usage, out byte[] plain_text);

        /// <summary>
        /// Decrypt an encrypted cipher text.
        /// </summary>
        /// <param name="key">The encryption key.</param>
        /// <param name="key_usage">The key usage for the decryption.</param>
        /// <param name="cipher_text">The cipher text.</param>
        /// <returns>The decrypted data.</returns>
        /// <exception cref="InvalidDataException">Thrown if can't decrypt.</exception>
        public byte[] Decrypt(byte[] key, byte[] cipher_text, KerberosKeyUsage key_usage)
        {
            if (!TryDecrypt(key, cipher_text, key_usage, out byte[] plain_text))
                throw new InvalidDataException("Can't decrypt the cipher text.");
            return plain_text;
        }

        /// <summary>
        /// Derive a key from a password.
        /// </summary>
        /// <param name="password">The password to derice from.</param>
        /// <param name="iterations">Iterations for the password derivation.</param>
        /// <param name="salt">Salt for the key.</param>
        /// <returns>The derived key.</returns>
        public abstract byte[] DeriveKey(string password, int iterations, string salt);

        /// <summary>
        /// Generate a random key.
        /// </summary>
        /// <returns>The derived key.</returns>
        public virtual byte[] GenerateKey()
        {
            using (var rand = RandomNumberGenerator.Create())
            {
                byte[] key = new byte[KeySize];
                rand.GetBytes(key);
                return key;
            }
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Size of the checksum.
        /// </summary>
        public int ChecksumSize { get; }

        /// <summary>
        /// Size of any additional encryption artifacts.
        /// </summary>
        public int AdditionalEncryptionSize { get; }

        /// <summary>
        /// The size of an encrypted block.
        /// </summary>
        public int BlockSize { get; }

        /// <summary>
        /// The size of the key.
        /// </summary>
        public int KeySize { get; }

        /// <summary>
        /// Get the Kerberos encryption type associated with the encryption algorithm.
        /// </summary>
        public KerberosEncryptionType EncryptionType { get; }

        /// <summary>
        /// Get the checksum type associated with the encryption algorithm.
        /// </summary>
        public KerberosChecksumType ChecksumType { get; }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="encryption_type">The Kerberos encryption type associated with the encryption algorithm.</param>
        /// <param name="checksum_type">The checksum type associated with the encryption algorithm.</param>
        /// <param name="checksum_size">Size of the checksum.</param>
        /// <param name="additional_encryption_size">Size of any additional encryption artifacts.</param>
        /// <param name="block_size">The size of an encrypted block.</param>
        /// <param name="key_size"></param>
        protected KerberosEncryptionEngine(KerberosEncryptionType encryption_type, 
            KerberosChecksumType checksum_type, int checksum_size, int additional_encryption_size,
            int block_size, int key_size)
        {
            EncryptionType = encryption_type;
            ChecksumType = checksum_type;
            ChecksumSize = checksum_size;
            AdditionalEncryptionSize = additional_encryption_size;
            BlockSize = block_size;
            KeySize = key_size;
        }
        #endregion

        #region Public Static Members
        /// <summary>
        /// Register a new encryption engine.
        /// </summary>
        /// <param name="engine">The encryption engine to register.</param>
        public static void Register(KerberosEncryptionEngine engine)
        {
            InitDefaultEngines();
            AddEngine(engine);
        }

        /// <summary>
        /// Get encryption engine by type.
        /// </summary>
        /// <param name="encryption_type">The encryption type.</param>
        /// <returns>The encryption engine.</returns>
        /// <exception cref="ArgumentException">Thrown if unknown encryption type.</exception>
        public static KerberosEncryptionEngine Get(KerberosEncryptionType encryption_type)
        {
            return Get(encryption_type, true);
        }

        /// <summary>
        /// Get the encryption algorithms supported on this system.
        /// </summary>
        /// <returns>The list of supported encryption systems.</returns>
        public static IReadOnlyCollection<KerberosEncryptionEngine> GetSystemSupported()
        {
            var types = KerberosEncryptionEngineNative.GetSupportedTypes();
            if (types.Length == 0)
                return _engines.Values.ToList().AsReadOnly();
            return types.Select(t => Get(t, false)).ToList().AsReadOnly();
        }

        internal static KerberosEncryptionEngine Get(KerberosEncryptionType encryption_type, bool throw_on_unsupported)
        {
            InitDefaultEngines();
            if (_engines.TryGetValue(encryption_type, out KerberosEncryptionEngine engine))
                return engine;

            return AddEngine(KerberosEncryptionEngineNative.GetNative(encryption_type, throw_on_unsupported));
        }

        #endregion
    }
}
