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
using NtApiDotNet.Utilities.Text;
using System;
using System.ComponentModel;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent Kerberos Encrypted Data.
    /// </summary>
    public class KerberosEncryptedData
    {
        /// <summary>
        /// Encryption type for the CipherText.
        /// </summary>
        public KerberosEncryptionType EncryptionType { get; private set; }
        /// <summary>
        /// Key version number.
        /// </summary>
        public int? KeyVersion { get; private set; }
        /// <summary>
        /// Cipher Text.
        /// </summary>
        public byte[] CipherText { get; private set; }

        internal KerberosEncryptedData()
        {
            CipherText = new byte[0];
        }

        private protected KerberosEncryptedData(KerberosEncryptionType type, 
            int? key_version, byte[] cipher_text)
        {
            EncryptionType = type;
            KeyVersion = key_version;
            CipherText = cipher_text;
        }

        internal virtual string Format()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine($"Encryption Type : {EncryptionType}");
            if (KeyVersion.HasValue)
            {
                builder.AppendLine($"Key Version     : {KeyVersion}");
            }
            HexDumpBuilder hex = new HexDumpBuilder(false, true, false, false, 0);
            hex.Append(CipherText);
            hex.Complete();
            builder.AppendLine($"Cipher Text     :");
            builder.Append(hex);
            return builder.ToString();
        }

        private bool DecryptRC4WithKey(KerberosKey key, KeyUsage key_usage, out byte[] decrypted)
        {
            HMACMD5 hmac = new HMACMD5(key.Key);
            byte[] key1 = hmac.ComputeHash(BitConverter.GetBytes((int)key_usage));
            hmac = new HMACMD5(key1);

            byte[] checksum = new byte[16];
            Buffer.BlockCopy(CipherText, 0, checksum, 0, checksum.Length);
            byte[] key2 = hmac.ComputeHash(checksum);

            byte[] result = ARC4.Transform(CipherText, 16, CipherText.Length - 16, key2);
            hmac = new HMACMD5(key1);
            byte[] calculated_checksum = hmac.ComputeHash(result);

            decrypted = new byte[result.Length - 8];
            Buffer.BlockCopy(result, 8, decrypted, 0, decrypted.Length);
            return NtObjectUtils.EqualByteArray(checksum, calculated_checksum);
        }

        private const int AES_BLOCK_SIZE = 16;
        private const int AES_CHECKSUM_SIZE = 12;
        private const int AES_CONFOUNDER_SIZE = 16;

        private static byte[] _aes_encrypt_ticket = new byte[] { 0xB5, 0xB0, 0x58, 0x2C, 0x14, 0xB6, 0x50, 0x0A, 0xAD, 0x56, 0xAB, 0x55, 0xAA, 0x80, 0x55, 0x6A };
        private static byte[] _aes_verify_ticket = new byte[] { 0x62, 0xDC, 0x6E, 0x37, 0x1A, 0x63, 0xA8, 0x09, 0x58, 0xAC, 0x56, 0x2B, 0x15, 0x40, 0x4A, 0xC5 };
        private static byte[] _aes_encrypt_auth = new byte[] { 0xFE, 0x54, 0xAA, 0x55, 0xA5, 0x02, 0x52, 0x2F, 0xBF, 0x5F, 0xAF, 0xD7, 0xEA, 0x81, 0x75, 0xFA };
        private static byte[] _aes_verify_auth = new byte[] { 0xAB, 0x80, 0xC0, 0x60, 0xAA, 0xAF, 0xAA, 0x2E, 0x6A, 0xB5, 0x5A, 0xAD, 0x55, 0x41, 0x6B, 0x55 };

        private static byte[] _aes_encrypt_ap_rep = new byte[] { 0x05, 0xD7, 0xEC, 0x76, 0xB5, 0x0B, 0x53, 0x33, 0xC1, 0x60, 0xB0, 0x58, 0x2A, 0x81, 0x96, 0x0B };
        private static byte[] _aes_verify_ap_rep = new byte[] { 0xB3, 0x04, 0x02, 0x81, 0xBA, 0xB8, 0xAB, 0x32, 0x6C, 0xB6, 0x5B, 0x2D, 0x95, 0x41, 0x8B, 0x65 };
        private static byte[] _aes_encrypt_krb_cred = new byte[] { 0x15, 0xE0, 0x70, 0xB8, 0xD5, 0x1C, 0x53, 0x3B, 0xC5, 0x62, 0xB1, 0x58, 0xAA, 0x81, 0xD6, 0x2B };
        private static byte[] _aes_verify_krb_cred = new byte[] { 0xC3, 0x0C, 0x86, 0xC3, 0xDA, 0xC9, 0xAB, 0x3A, 0x70, 0xB8, 0x5C, 0x2E, 0x15, 0x41, 0xCB, 0x85 };

        private static void SwapEndBlocks(byte[] cipher_text)
        {
            if (cipher_text.Length < AES_BLOCK_SIZE*2)
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
            AesManaged aes = new AesManaged();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            aes.IV = new byte[16];
            var dec = aes.CreateDecryptor();
            byte[] block = new byte[AES_BLOCK_SIZE];
            dec.TransformBlock(cipher_text, offset, AES_BLOCK_SIZE, block, 0);
            return block;
        }

        private bool DecryptAESWithKey(KerberosKey key, KeyUsage key_usage, out byte[] decrypted)
        {
            byte[] derive_enc_key;
            byte[] derive_mac_key;

            switch (key_usage)
            {
                case KeyUsage.AsRepTgsRepTicket:
                    derive_enc_key = _aes_encrypt_ticket;
                    derive_mac_key = _aes_verify_ticket;
                    break;
                case KeyUsage.ApReqAuthSubKey:
                    derive_enc_key = _aes_encrypt_auth;
                    derive_mac_key = _aes_verify_auth;
                    break;
                case KeyUsage.ApRepEncryptedPart:
                    derive_enc_key = _aes_encrypt_ap_rep;
                    derive_mac_key = _aes_verify_ap_rep;
                    break;
                case KeyUsage.KrbCred:
                    derive_enc_key = _aes_encrypt_krb_cred;
                    derive_mac_key = _aes_verify_krb_cred;
                    break;
                default:
                    throw new ArgumentException("Unknown key usage type.");
            }

            byte[] new_key = KerberosKey.DeriveAesKey(key.Key, derive_enc_key);

            int cipher_text_length = CipherText.Length - AES_CHECKSUM_SIZE;
            int remaining = AES_BLOCK_SIZE - (cipher_text_length % AES_BLOCK_SIZE);
            decrypted = new byte[AlignBlock(cipher_text_length)];
            Array.Copy(CipherText, decrypted, cipher_text_length);

            if (remaining > 0)
            {
                byte[] decrypted_block = DecryptAESBlock(new_key, decrypted, decrypted.Length - (AES_BLOCK_SIZE * 2));
                Array.Copy(decrypted_block, AES_BLOCK_SIZE - remaining, decrypted, decrypted.Length - remaining, remaining);
            }

            SwapEndBlocks(decrypted);

            AesManaged aes = new AesManaged();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            aes.Key = new_key;
            aes.IV = new byte[16];
            var dec = aes.CreateDecryptor();
            dec.TransformBlock(decrypted, 0, decrypted.Length, decrypted, 0);

            // Obviously not a secure check. This is for information only.
            HMACSHA1 hmac = new HMACSHA1(KerberosKey.DeriveAesKey(key.Key, derive_mac_key));
            byte[] hash = hmac.ComputeHash(decrypted, 0, cipher_text_length);
            for (int i = 0; i < AES_CHECKSUM_SIZE; ++i)
            {
                if (hash[i] != CipherText[cipher_text_length + i])
                    return false;
            }
            Array.Copy(decrypted, AES_CONFOUNDER_SIZE, decrypted, 0, cipher_text_length - AES_CONFOUNDER_SIZE);
            Array.Resize(ref decrypted, cipher_text_length - AES_CONFOUNDER_SIZE);
            return true;
        }

        private bool DecryptRC4(KerberosKeySet keyset, string realm, KerberosPrincipalName server_name, KeyUsage key_usage, out byte[] decrypted)
        {
            KerberosKey key = keyset.FindKey(EncryptionType, server_name.NameType, server_name.GetPrincipal(realm), KeyVersion ?? 0);
            if (key != null)
            {
                if (DecryptRC4WithKey(key, key_usage, out decrypted))
                    return true;
            }
            foreach (var next in keyset.GetKeysForEncryption(EncryptionType))
            {
                if (DecryptRC4WithKey(next, key_usage, out decrypted))
                    return true;
            }
            decrypted = null;
            return false;
        }

        private bool DecryptAES(KerberosKeySet keyset, string realm, KerberosPrincipalName server_name, KeyUsage key_usage, out byte[] decrypted)
        {
            KerberosKey key = keyset.FindKey(EncryptionType, server_name.NameType, server_name.GetPrincipal(realm), KeyVersion ?? 0);
            if (key != null)
            {
                if (DecryptAESWithKey(key, key_usage, out decrypted))
                    return true;
            }
            foreach (var next in keyset.GetKeysForEncryption(EncryptionType))
            {
                if (DecryptAESWithKey(next, key_usage, out decrypted))
                    return true;
            }
            decrypted = null;
            return false;
        }

        internal bool Decrypt(KerberosKeySet keyset, string realm, KerberosPrincipalName server_name, KeyUsage key_usage, out byte[] decrypted)
        {
            if (EncryptionType == KerberosEncryptionType.ARCFOUR_HMAC_MD5)
            {
                return DecryptRC4(keyset, realm, server_name, key_usage, out decrypted);
            }
            else if (EncryptionType == KerberosEncryptionType.AES128_CTS_HMAC_SHA1_96 
                || EncryptionType == KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96)
            {
                return DecryptAES(keyset, realm, server_name, key_usage, out decrypted);
            }
            decrypted = null;
            return false;
        }

        internal static KerberosEncryptedData Parse(DERValue value)
        {
            if (!value.CheckSequence())
                throw new InvalidDataException();

            KerberosEncryptedData ret = new KerberosEncryptedData();
            foreach (var next in value.Children)
            {
                if (next.Type != DERTagType.ContextSpecific)
                    throw new InvalidDataException();
                switch (next.Tag)
                {
                    case 0:
                        ret.EncryptionType = (KerberosEncryptionType)next.ReadChildInteger();
                        break;
                    case 1:
                        ret.KeyVersion = next.ReadChildInteger();
                        break;
                    case 2:
                        ret.CipherText = next.ReadChildOctetString();
                        break;
                    default:
                        throw new InvalidDataException();
                }
            }
            return ret;
        }
    }
}
