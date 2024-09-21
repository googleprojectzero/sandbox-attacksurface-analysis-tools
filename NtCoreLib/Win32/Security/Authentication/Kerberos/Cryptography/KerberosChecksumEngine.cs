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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Cryptography
{
    /// <summary>
    /// Base class for a Kerberos checksum engine.
    /// </summary>
    public abstract class KerberosChecksumEngine
    {
        #region Private Members
        private static Dictionary<KerberosChecksumType, KerberosChecksumEngine> _engines;

        private static KerberosChecksumEngine AddEngine(KerberosChecksumEngine engine)
        {
            _engines.Add(engine.ChecksumType, engine);
            return engine;
        }

        private static void InitDefaultEngines()
        {
            if (_engines != null)
                return;
            _engines = new Dictionary<KerberosChecksumType, KerberosChecksumEngine>();
            AddEngine(new KerberosChecksumEngineHMACMD5());
            AddEngine(KerberosChecksumEngineAESSHA196.AES128);
            AddEngine(KerberosChecksumEngineAESSHA196.AES256);
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="checksum_type">The checksum type.</param>
        /// <param name="checksum_size">The checksum size.</param>
        protected KerberosChecksumEngine(KerberosChecksumType checksum_type, int checksum_size)
        {
            ChecksumType = checksum_type;
            ChecksumSize = checksum_size;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Compute a hash for a set of data.
        /// </summary>
        /// <param name="key">The key for the checksum (might not be required)</param>
        /// <param name="data">The data to hash.</param>
        /// <param name="offset">Offset into the data to hash.</param>
        /// <param name="length">The length of the data to hash.</param>
        /// <param name="key_usage">The key usage.</param>
        /// <returns>The computed hash.</returns>
        public abstract byte[] ComputeHash(byte[] key, byte[] data, int offset, int length, KerberosKeyUsage key_usage);

        /// <summary>
        /// Compute a hash for a set of data.
        /// </summary>
        /// <param name="key">The key for the checksum (might not be required)</param>
        /// <param name="data">The data to hash.</param>
        /// <param name="key_usage">The key usage.</param>
        /// <returns>The computed hash.</returns>
        public byte[] ComputeHash(byte[] key, byte[] data, KerberosKeyUsage key_usage)
        {
            return ComputeHash(key, data, 0, data.Length, key_usage);
        }

        /// <summary>
        /// Verify a hash.
        /// </summary>
        /// <param name="key">The key for the checksum (might not be required)</param>
        /// <param name="hash">The hash to verify.</param>
        /// <param name="data">The data to hash.</param>
        /// <param name="offset">Offset into the data to hash.</param>
        /// <param name="length">The length of the data to hash.</param>
        /// <param name="key_usage">The key usage.</param>
        /// <returns>True if the hash matches.</returns>
        public bool VerifyHash(byte[] key, byte[] hash, byte[] data, int offset, int length, KerberosKeyUsage key_usage)
        {
            if (hash is null)
            {
                throw new ArgumentNullException(nameof(hash));
            }

            return NtObjectUtils.EqualByteArray(hash, ComputeHash(key, data, offset, length, key_usage));
        }

        /// <summary>
        /// Verify a hash.
        /// </summary>
        /// <param name="key">The key for the checksum (might not be required)</param>
        /// <param name="hash">The hash to verify.</param>
        /// <param name="data">The data to hash.</param>
        /// <param name="key_usage">The key usage.</param>
        /// <returns>True if the hash matches.</returns>
        public bool VerifyHash(byte[] key, byte[] hash, byte[] data, KerberosKeyUsage key_usage)
        {
            return VerifyHash(key, hash, data, 0, data.Length, key_usage);
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Size of the checksum.
        /// </summary>
        public int ChecksumSize { get; }

        /// <summary>
        /// Get the checksum type.
        /// </summary>
        public KerberosChecksumType ChecksumType { get; }
        #endregion

        #region Public Static Methods
        /// <summary>
        /// Register a new checksum engine.
        /// </summary>
        /// <param name="engine">The checksum engine to register.</param>
        public static void Register(KerberosChecksumEngine engine)
        {
            InitDefaultEngines();
            AddEngine(engine);
        }

        /// <summary>
        /// Get checksum engine by type.
        /// </summary>
        /// <param name="checksum_type">The checksum type.</param>
        /// <returns>The checksum engine.</returns>
        /// <exception cref="ArgumentException">Thrown if unknown checksum type.</exception>
        public static KerberosChecksumEngine Get(KerberosChecksumType checksum_type)
        {
            return Get(checksum_type, true);
        }

        internal static KerberosChecksumEngine Get(KerberosChecksumType checksum_type, bool throw_on_unsupported)
        {
            InitDefaultEngines();
            if (_engines.TryGetValue(checksum_type, out KerberosChecksumEngine engine))
                return engine;
            return AddEngine(KerberosChecksumEngineNative.GetNative(checksum_type, throw_on_unsupported));
        }
        #endregion
    }
}
