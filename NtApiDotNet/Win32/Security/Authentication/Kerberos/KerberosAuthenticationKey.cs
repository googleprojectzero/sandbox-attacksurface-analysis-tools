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
    public sealed class KerberosAuthenticationKey : AuthenticationKey, IDERObject
    {
        #region Public Properties
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
        /// Size of the checksum.
        /// </summary>
        public int ChecksumSize
        {
            get
            {
                switch (KeyEncryption)
                {
                    case KerberosEncryptionType.ARCFOUR_HMAC_MD5:
                        return MD5_CHECKSUM_SIZE;
                    case KerberosEncryptionType.AES128_CTS_HMAC_SHA1_96:
                    case KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96:
                        return AES_CHECKSUM_SIZE;
                    default:
                        throw new InvalidDataException("Unsupported encryption algorithm.");
                }
            }
        }
        /// <summary>
        /// Size of any additional encryption artifacts.
        /// </summary>
        public int AdditionalEncryptionSize
        {
            get
            {
                switch (KeyEncryption)
                {
                    case KerberosEncryptionType.ARCFOUR_HMAC_MD5:
                        return MD5_CHECKSUM_SIZE + RC4_NONCE_LENGTH;
                    case KerberosEncryptionType.AES128_CTS_HMAC_SHA1_96:
                    case KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96:
                        return AES_CHECKSUM_SIZE + AES_CONFOUNDER_SIZE;
                    default:
                        throw new InvalidDataException("Unsupported encryption algorithm.");
                }
            }
        }
        /// <summary>
        /// Returns whether the key is all zeros typically indicating it's invalid.
        /// </summary>
        public bool IsZeroKey => NtObjectUtils.EqualByteArray(Key, new byte[Key.Length]);

        /// <summary>
        /// Get the checksum type associated with the key algorithm.
        /// </summary>
        public KerberosChecksumType ChecksumType
        {
            get
            {
                switch (KeyEncryption)
                {
                    case KerberosEncryptionType.AES128_CTS_HMAC_SHA1_96:
                        return KerberosChecksumType.HMAC_SHA1_96_AES_128;
                    case KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96:
                        return KerberosChecksumType.HMAC_SHA1_96_AES_256;
                    case KerberosEncryptionType.ARCFOUR_HMAC_MD5:
                        return KerberosChecksumType.HMAC_MD5;
                    default:
                        throw new InvalidDataException("Unsupported hash algorithm.");
                }
            }
        }

        /// <summary>
        /// The kerberos principal name.
        /// </summary>
        public KerberosPrincipalName Name => new KerberosPrincipalName(NameType, Components);
        #endregion

        #region Constructors
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

        /// <summary>
        /// Generate a random key.
        /// </summary>
        /// <param name="key_encryption">The encryption type for the key.</param>
        /// <returns>The generated key.</returns>
        public static KerberosAuthenticationKey GenerateKey(KerberosEncryptionType key_encryption)
        {
            int key_length;
            switch (key_encryption)
            {
                case KerberosEncryptionType.ARCFOUR_HMAC_MD5:
                case KerberosEncryptionType.AES128_CTS_HMAC_SHA1_96:
                    key_length = 16;
                    break;
                case KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96:
                    key_length = 32;
                    break;
                default:
                    throw new ArgumentException("Unsupported key encryption type.");
            }

            byte[] key = new byte[key_length];
            new Random().NextBytes(key);
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
            switch (KeyEncryption)
            {
                case KerberosEncryptionType.ARCFOUR_HMAC_MD5:
                    return DecryptRC4(cipher_text, key_usage, out plain_text);
                case KerberosEncryptionType.AES128_CTS_HMAC_SHA1_96:
                case KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96:
                    return DecryptAES(cipher_text, key_usage, out plain_text);
            }
            plain_text = null;
            return false;
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
            switch (KeyEncryption)
            {
                case KerberosEncryptionType.ARCFOUR_HMAC_MD5:
                case KerberosEncryptionType.AES128_CTS_HMAC_SHA1_96:
                case KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96:
                    break;
                default:
                    throw new InvalidDataException("Unsupported encryption algorithm.");
            }
            if (!TryDecrypt(cipher_text, key_usage, out byte[] plain_text))
                throw new InvalidDataException("Can't decrypt the cipher text.");
            return plain_text;
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
            switch (KeyEncryption)
            {
                case KerberosEncryptionType.ARCFOUR_HMAC_MD5:
                    return EncryptRC4(plain_text, key_usage);
                case KerberosEncryptionType.AES128_CTS_HMAC_SHA1_96:
                case KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96:
                    return EncryptAES(plain_text, key_usage);
                default:
                    throw new InvalidDataException("Unsupported encryption algorithm.");
            }
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
            switch (KeyEncryption)
            {
                case KerberosEncryptionType.ARCFOUR_HMAC_MD5:
                    return ComputeMD5HMACHash(data, offset, length, key_usage);
                case KerberosEncryptionType.AES128_CTS_HMAC_SHA1_96:
                case KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96:
                    return ComputeSHA1HMACHash(data, offset, length, key_usage);
                default:
                    throw new InvalidDataException("Unsupported hash algorithm.");
            }
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
        /// Compute an MD5 HMAC hash for a set of data.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <param name="offset">Offset into the data to hash.</param>
        /// <param name="length">The length of the data to hash.</param>
        /// <param name="key_usage">The key usage.</param>
        /// <returns>The computed hash.</returns>
        public byte[] ComputeMD5HMACHash(byte[] data, int offset, int length, KerberosKeyUsage key_usage)
        {
            byte[] sign_key = new HMACMD5(_key).ComputeHash(Encoding.ASCII.GetBytes("signaturekey\0"));

            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            writer.Write((int)key_usage);
            writer.Write(data, offset, length);

            byte[] tmp = MD5.Create().ComputeHash(stm.ToArray());
            return new HMACMD5(sign_key).ComputeHash(tmp);
        }

        /// <summary>
        /// Compute an MD5 HMAC hash for a set of data.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <param name="key_usage">The key usage.</param>
        /// <returns>The computed hash.</returns>
        public byte[] ComputeMD5HMACHash(byte[] data, KerberosKeyUsage key_usage)
        {
            return ComputeMD5HMACHash(data, 0, data.Length, key_usage);
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

        private byte[] ComputeSHA1HMACHash(byte[] data, int offset, int length, KerberosKeyUsage key_usage)
        {
            byte[] derive_mac_key = DeriveTempKey(key_usage, SignatureKey);
            return new HMACSHA1(DeriveAesKey(_key, derive_mac_key)).ComputeHash(data, 
                offset, length).Take(AES_CHECKSUM_SIZE).ToArray();
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

        private const int MD5_CHECKSUM_SIZE = 16;
        private const int RC4_NONCE_LENGTH = 8;

        private bool DecryptRC4(byte[] cipher_text, KerberosKeyUsage key_usage, out byte[] plain_text)
        {
            HMACMD5 hmac = new HMACMD5(_key);
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

        private byte[] EncryptRC4(byte[] plain_text, KerberosKeyUsage key_usage)
        {
            HMACMD5 hmac = new HMACMD5(_key);
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

        private const int AES_BLOCK_SIZE = 16;
        private const int AES_CHECKSUM_SIZE = 12;
        private const int AES_CONFOUNDER_SIZE = 16;

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

        private const byte EncryptionKey = 0xAA;
        private const byte VerificationKey = 0x55;
        private const byte SignatureKey = 0x99;

        private static byte[] DeriveAesKey(string password, string salt, int iterations, int key_size)
        {
            Rfc2898DeriveBytes pbkdf = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(password), Encoding.UTF8.GetBytes(salt), iterations);
            return DeriveAesKey(pbkdf.GetBytes(key_size), NFold.Compute("kerberos", 16));
        }

        private byte[] DeriveTempKey(KerberosKeyUsage key_usage, byte key_type)
        {
            byte[] r = BitConverter.GetBytes((int)key_usage).Reverse().ToArray();
            Array.Resize(ref r, 5);
            r[4] = key_type;
            return NFold.Compute(r, 16);
        }

        private bool DecryptAES(byte[] cipher_text, KerberosKeyUsage key_usage, out byte[] plain_text)
        {
            byte[] derive_enc_key = DeriveTempKey(key_usage, EncryptionKey);
            byte[] derive_mac_key = DeriveTempKey(key_usage, VerificationKey);

            byte[] new_key = DeriveAesKey(_key, derive_enc_key);

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
            HMACSHA1 hmac = new HMACSHA1(DeriveAesKey(_key, derive_mac_key));
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

        private byte[] EncryptAES(byte[] plain_text, KerberosKeyUsage key_usage)
        {
            byte[] derive_enc_key = DeriveTempKey(key_usage, EncryptionKey);
            byte[] derive_mac_key = DeriveTempKey(key_usage, VerificationKey);

            byte[] cipher_text = new byte[AES_CONFOUNDER_SIZE];
            new Random().NextBytes(cipher_text);
            int plain_text_length = plain_text.Length + AES_CONFOUNDER_SIZE;

            HMACSHA1 hmac = new HMACSHA1(DeriveAesKey(_key, derive_mac_key));
            Array.Resize(ref cipher_text, AlignBlock(plain_text_length));
            Array.Copy(plain_text, 0, cipher_text, AES_CONFOUNDER_SIZE, plain_text.Length);
            byte[] hash = hmac.ComputeHash(cipher_text, 0, plain_text_length);

            byte[] new_key = DeriveAesKey(_key, derive_enc_key);
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

        #endregion
    }
}
