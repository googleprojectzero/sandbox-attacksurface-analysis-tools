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

        private bool DecryptRC4WithKey(KerberosKey key, RC4KeyUsage key_usage, out byte[] decrypted)
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

        private bool DecryptRC4(KerberosKeySet keyset, string realm, KerberosPrincipalName server_name, RC4KeyUsage key_usage, out byte[] decrypted)
        {
            KerberosKey key = keyset.FindKey(EncryptionType, server_name.NameType, server_name.GetPrincipal(realm), KeyVersion ?? 0);
            if (key != null)
            {
                if (DecryptRC4WithKey(key, key_usage, out decrypted))
                    return true;
            }
            foreach (var next in keyset.GetKeysForEncryption(EncryptionType))
            {
                if (DecryptRC4WithKey(key, key_usage, out decrypted))
                    return true;
            }
            decrypted = null;
            return false;
        }

        internal bool Decrypt(KerberosKeySet keyset, string realm, KerberosPrincipalName server_name, RC4KeyUsage key_usage, out byte[] decrypted)
        {
            if (EncryptionType == KerberosEncryptionType.ARCFOUR_HMAC_MD5)
            {
                return DecryptRC4(keyset, realm, server_name, key_usage, out decrypted);
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
