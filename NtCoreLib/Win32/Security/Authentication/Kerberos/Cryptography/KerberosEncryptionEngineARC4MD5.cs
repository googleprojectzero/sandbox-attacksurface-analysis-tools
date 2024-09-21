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

using NtApiDotNet.Utilities.Security;
using System;
using System.Security.Cryptography;
using System.Text;
using static NtApiDotNet.Win32.Security.Authentication.Kerberos.Cryptography.KerberosEncryptionUtils;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Cryptography
{
    /// <summary>
    /// Class to represent an ARC4 MD5 HMAC encryption engine.
    /// </summary>
    internal sealed class KerberosEncryptionEngineARC4MD5 : KerberosEncryptionEngine
    {
        #region Private Members
        private const int RC4_NONCE_LENGTH = 8;
        #endregion

        #region Public Methods
        /// <summary>
        /// Derive a key from a password.
        /// </summary>
        /// <remarks>Not all encryption types are supported.</remarks>
        /// <param name="password">The password to derice from.</param>
        /// <param name="iterations">Iterations for the password derivation.</param>
        /// <param name="salt">Salt for the key.</param>
        /// <returns>The derived key.</returns>
        public override byte[] DeriveKey(string password, int iterations, string salt)
        {
            if (password is null)
            {
                throw new ArgumentNullException(nameof(password));
            }

            return MD4.CalculateHash(Encoding.Unicode.GetBytes(password));
        }

        /// <summary>
        /// Encrypt a buffer.
        /// </summary>
        /// <param name="key">The encryption key.</param>
        /// <param name="plain_text">The plain text to encrypt.</param>
        /// <param name="key_usage">The key usage.</param>
        /// <returns>The encrypted data.</returns>
        public override byte[] Encrypt(byte[] key, byte[] plain_text, KerberosKeyUsage key_usage)
        {
            HMACMD5 hmac = new HMACMD5(key);
            byte[] key1 = hmac.ComputeHash(BitConverter.GetBytes((int)key_usage));
            hmac = new HMACMD5(key1);

            byte[] enc_buffer = new byte[RC4_NONCE_LENGTH];
            new Random().NextBytes(enc_buffer);
            Array.Resize(ref enc_buffer, RC4_NONCE_LENGTH + plain_text.Length);
            Buffer.BlockCopy(plain_text, 0, enc_buffer, RC4_NONCE_LENGTH, plain_text.Length);

            byte[] checksum = hmac.ComputeHash(enc_buffer);
            byte[] key2 = hmac.ComputeHash(checksum);
            enc_buffer = ARC4.Transform(enc_buffer, 0, enc_buffer.Length, key2);
            byte[] cipher_text = new byte[enc_buffer.Length + MD5_CHECKSUM_SIZE];
            Buffer.BlockCopy(checksum, 0, cipher_text, 0, MD5_CHECKSUM_SIZE);
            Buffer.BlockCopy(enc_buffer, 0, cipher_text, MD5_CHECKSUM_SIZE, enc_buffer.Length);
            return cipher_text;
        }

        /// <summary>
        /// Try and decrypt an encrypted cipher text.
        /// </summary>
        /// <param name="key">The encryption key.</param>
        /// <param name="key_usage">The key usage for the decryption.</param>
        /// <param name="plain_text">The plain text.</param>
        /// <param name="cipher_text">The cipher text.</param>
        /// <returns>True if successfully decrypted.</returns>
        public override bool TryDecrypt(byte[] key, byte[] cipher_text, KerberosKeyUsage key_usage, out byte[] plain_text)
        {
            HMACMD5 hmac = new HMACMD5(key);
            byte[] key1 = hmac.ComputeHash(BitConverter.GetBytes((int)key_usage));
            hmac = new HMACMD5(key1);

            byte[] checksum = new byte[MD5_CHECKSUM_SIZE];
            Buffer.BlockCopy(cipher_text, 0, checksum, 0, checksum.Length);
            byte[] key2 = hmac.ComputeHash(checksum);

            byte[] result = ARC4.Transform(cipher_text, MD5_CHECKSUM_SIZE, cipher_text.Length - MD5_CHECKSUM_SIZE, key2);
            hmac = new HMACMD5(key1);
            byte[] calculated_checksum = hmac.ComputeHash(result);

            plain_text = new byte[result.Length - RC4_NONCE_LENGTH];
            Buffer.BlockCopy(result, RC4_NONCE_LENGTH, plain_text, 0, plain_text.Length);
            return NtObjectUtils.EqualByteArray(checksum, calculated_checksum);
        }
        #endregion

        #region Internal Members
        internal KerberosEncryptionEngineARC4MD5() : base(KerberosEncryptionType.ARCFOUR_HMAC_MD5, KerberosChecksumType.HMAC_MD5,
            MD5_CHECKSUM_SIZE, MD5_CHECKSUM_SIZE + RC4_NONCE_LENGTH, 1, MD5_CHECKSUM_SIZE, "RSADSI RC4-HMAC")
        {
        }
        #endregion
    }
}
