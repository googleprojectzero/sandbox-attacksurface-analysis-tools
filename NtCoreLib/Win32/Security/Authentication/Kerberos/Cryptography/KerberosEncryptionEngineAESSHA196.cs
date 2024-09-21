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
    /// Class to represent AES encryption with SHA1-96 hash.
    /// </summary>
    internal sealed class KerberosEncryptionEngineAESSHA196 : KerberosEncryptionEngine
    {
        #region Private Members
        private const int AES_BLOCK_SIZE = 16;
        private const int AES_CONFOUNDER_SIZE = 16;
        private const byte EncryptionKey = 0xAA;
        private const byte VerificationKey = 0x55;

        private static string GetName(KerberosEncryptionType encryption_type)
        {
            switch (encryption_type)
            {
                case KerberosEncryptionType.AES128_CTS_HMAC_SHA1_96:
                    return "Kerberos AES128-CTS-HMAC-SHA1-96";
                case KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96:
                    return "Kerberos AES256-CTS-HMAC-SHA1-96";
            }
            return null;
        }

        private KerberosEncryptionEngineAESSHA196(KerberosEncryptionType encryption_type, KerberosChecksumType checksum_type)
            : base(encryption_type, checksum_type, AES_CHECKSUM_SIZE, AES_CHECKSUM_SIZE + AES_CONFOUNDER_SIZE, AES_BLOCK_SIZE,
                  encryption_type == KerberosEncryptionType.AES128_CTS_HMAC_SHA1_96 ? 16 : 32, GetName(encryption_type))
        {
        }

        private static void SwapEndBlocks(byte[] cipher_text)
        {
            if (cipher_text.Length < AES_BLOCK_SIZE * 2)
            {
                return;
            }

            byte[] block = new byte[AES_BLOCK_SIZE];
            Array.Copy(cipher_text, cipher_text.Length - AES_BLOCK_SIZE, block, 0, AES_BLOCK_SIZE);
            Array.Copy(cipher_text, cipher_text.Length - (2 * AES_BLOCK_SIZE), cipher_text, cipher_text.Length - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            Array.Copy(block, 0, cipher_text, cipher_text.Length - (2 * AES_BLOCK_SIZE), AES_BLOCK_SIZE);
        }

        private static int AlignBlock(int size)
        {
            return (size + (AES_BLOCK_SIZE - 1)) & ~(AES_BLOCK_SIZE - 1);
        }

        private byte[] DecryptAESBlock(byte[] key, byte[] cipher_text, int offset)
        {
            AesManaged aes = new AesManaged
            {
                Mode = CipherMode.ECB,
                Padding = PaddingMode.None,
                Key = key,
                IV = new byte[16]
            };
            var dec = aes.CreateDecryptor();
            byte[] block = new byte[AES_BLOCK_SIZE];
            dec.TransformBlock(cipher_text, offset, AES_BLOCK_SIZE, block, 0);
            return block;
        }

        private byte[] EncryptAESBlock(byte[] key, byte[] cipher_text, int offset)
        {
            AesManaged aes = new AesManaged
            {
                Mode = CipherMode.ECB,
                Padding = PaddingMode.None,
                Key = key,
                IV = new byte[16]
            };
            var enc = aes.CreateEncryptor();
            byte[] block = new byte[AES_BLOCK_SIZE];
            enc.TransformBlock(cipher_text, offset, AES_BLOCK_SIZE, block, 0);
            return block;
        }

        private static byte[] DeriveAesKey(string password, string salt, int iterations, int key_size)
        {
            Rfc2898DeriveBytes pbkdf = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(password), Encoding.UTF8.GetBytes(salt), iterations);
            return KerberosEncryptionUtils.DeriveAesKey(pbkdf.GetBytes(key_size), NFold.Compute("kerberos", 16));
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
        public override byte[] Encrypt(byte[] key, byte[] plain_text, KerberosKeyUsage key_usage)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (key.Length != KeySize)
            {
                throw new ArgumentNullException("Invalid key size for algorithm.", nameof(key));
            }

            if (plain_text is null)
            {
                throw new ArgumentNullException(nameof(plain_text));
            }

            byte[] derive_enc_key = DeriveTempKey(key_usage, EncryptionKey);
            byte[] derive_mac_key = DeriveTempKey(key_usage, VerificationKey);

            byte[] cipher_text = new byte[AES_CONFOUNDER_SIZE];
            new Random().NextBytes(cipher_text);
            int plain_text_length = plain_text.Length + AES_CONFOUNDER_SIZE;

            HMACSHA1 hmac = new HMACSHA1(KerberosEncryptionUtils.DeriveAesKey(key, derive_mac_key));
            Array.Resize(ref cipher_text, AlignBlock(plain_text_length));
            Array.Copy(plain_text, 0, cipher_text, AES_CONFOUNDER_SIZE, plain_text.Length);
            byte[] hash = hmac.ComputeHash(cipher_text, 0, plain_text_length);

            byte[] new_key = KerberosEncryptionUtils.DeriveAesKey(key, derive_enc_key);
            AesManaged aes = new AesManaged
            {
                Mode = CipherMode.CBC,
                Padding = PaddingMode.None,
                Key = new_key,
                IV = new byte[16]
            };
            var enc = aes.CreateEncryptor();
            enc.TransformBlock(cipher_text, 0, cipher_text.Length, cipher_text, 0);

            SwapEndBlocks(cipher_text);

            int remaining = AES_BLOCK_SIZE - (plain_text_length % AES_BLOCK_SIZE);
            if (remaining > 0 && remaining != AES_BLOCK_SIZE)
            {
                byte[] encrypted_block = EncryptAESBlock(new_key, cipher_text, cipher_text.Length - (AES_BLOCK_SIZE * 2));
                Array.Copy(encrypted_block, AES_BLOCK_SIZE - remaining, cipher_text, cipher_text.Length - remaining, remaining);
            }

            Array.Resize(ref cipher_text, plain_text_length + AES_CHECKSUM_SIZE);
            Buffer.BlockCopy(hash, 0, cipher_text, cipher_text.Length - AES_CHECKSUM_SIZE, AES_CHECKSUM_SIZE);
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
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (key.Length != KeySize)
            {
                throw new ArgumentNullException("Invalid key size for algorithm.", nameof(key));
            }

            if (cipher_text is null)
            {
                throw new ArgumentNullException(nameof(cipher_text));
            }

            byte[] derive_enc_key = DeriveTempKey(key_usage, EncryptionKey);
            byte[] derive_mac_key = DeriveTempKey(key_usage, VerificationKey);

            byte[] new_key = KerberosEncryptionUtils.DeriveAesKey(key, derive_enc_key);

            int cipher_text_length = cipher_text.Length - AES_CHECKSUM_SIZE;
            int remaining = AES_BLOCK_SIZE - (cipher_text_length % AES_BLOCK_SIZE);
            plain_text = new byte[AlignBlock(cipher_text_length)];
            Array.Copy(cipher_text, plain_text, cipher_text_length);

            if (remaining > 0 && remaining != AES_BLOCK_SIZE)
            {
                byte[] decrypted_block = DecryptAESBlock(new_key, plain_text, plain_text.Length - (AES_BLOCK_SIZE * 2));
                Array.Copy(decrypted_block, AES_BLOCK_SIZE - remaining, plain_text, plain_text.Length - remaining, remaining);
            }

            SwapEndBlocks(plain_text);

            AesManaged aes = new AesManaged
            {
                Mode = CipherMode.CBC,
                Padding = PaddingMode.None,
                Key = new_key,
                IV = new byte[16]
            };
            var dec = aes.CreateDecryptor();
            dec.TransformBlock(plain_text, 0, plain_text.Length, plain_text, 0);

            // Obviously not a secure check. This is for information only.
            HMACSHA1 hmac = new HMACSHA1(KerberosEncryptionUtils.DeriveAesKey(key, derive_mac_key));
            byte[] hash = hmac.ComputeHash(plain_text, 0, cipher_text_length);
            for (int i = 0; i < AES_CHECKSUM_SIZE; ++i)
            {
                if (hash[i] != cipher_text[cipher_text_length + i])
                    return false;
            }
            Array.Copy(plain_text, AES_CONFOUNDER_SIZE, plain_text, 0, cipher_text_length - AES_CONFOUNDER_SIZE);
            Array.Resize(ref plain_text, cipher_text_length - AES_CONFOUNDER_SIZE);
            return true;
        }

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

            if (salt is null)
            {
                throw new ArgumentNullException(nameof(salt));
            }

            return DeriveAesKey(password, salt, iterations, KeySize);
        }
        #endregion

        #region Internal Members
        internal static KerberosEncryptionEngineAESSHA196 AES128 = new KerberosEncryptionEngineAESSHA196(KerberosEncryptionType.AES128_CTS_HMAC_SHA1_96, KerberosChecksumType.HMAC_SHA1_96_AES_128);
        internal static KerberosEncryptionEngineAESSHA196 AES256 = new KerberosEncryptionEngineAESSHA196(KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96, KerberosChecksumType.HMAC_SHA1_96_AES_256);
        #endregion
    }
}
