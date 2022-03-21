﻿//  Copyright 2020 Google Inc. All Rights Reserved.
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
using NtApiDotNet.Utilities.Text;
using System;
using System.IO;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent Kerberos Encrypted Data.
    /// </summary>
    public class KerberosEncryptedData : IDERObject
    {
        #region Public Properties
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
        #endregion

        #region Public Static Methods
        /// <summary>
        /// Create a new Kerberos EncryptedData object.
        /// </summary>
        /// <param name="encryption_type">The encryption type.</param>
        /// <param name="cipher_text">The cipher text.</param>
        /// <param name="key_version">The optional key version number.</param>
        /// <returns>The new EncryptedData object.</returns>
        public static KerberosEncryptedData Create(KerberosEncryptionType encryption_type, byte[] cipher_text, int? key_version = null)
        {
            if (cipher_text is null)
            {
                throw new ArgumentNullException(nameof(cipher_text));
            }

            return new KerberosEncryptedData(encryption_type, key_version, cipher_text);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Decrypt the encrypted data.
        /// </summary>
        /// <param name="key">The key to decrypt the data.</param>
        /// <param name="key_usage">The Kerberos key usage for the decryption.</param>
        /// <returns>The decrypted data.</returns>
        public KerberosEncryptedData Decrypt(KerberosAuthenticationKey key, KerberosKeyUsage key_usage)
        {
            byte[] cipher_text = CipherText;
            if (EncryptionType != KerberosEncryptionType.NULL)
                cipher_text = key.Decrypt(cipher_text, key_usage);
            return Create(KerberosEncryptionType.NULL, cipher_text, null);
        }

        /// <summary>
        /// Encrypt the data.
        /// </summary>
        /// <param name="key">The key to encrypt the data.</param>
        /// <param name="key_usage">The Kerberos key usage for the encryption.</param>
        /// <param name="key_version">Optional key version number.</param>
        /// <returns>The encrypted data.</returns>
        public KerberosEncryptedData Encrypt(KerberosAuthenticationKey key, KerberosKeyUsage key_usage, int? key_version = null)
        {
            if (EncryptionType != KerberosEncryptionType.NULL)
                throw new ArgumentException("Encryption type must be NULL.", nameof(EncryptionType));
            byte[] cipher_text = key.Encrypt(CipherText, key_usage);
            return Create(key.KeyEncryption, cipher_text, key_version);
        }
        #endregion

        #region Constructors
        internal KerberosEncryptedData() 
            : this(KerberosEncryptionType.NULL, null, Array.Empty<byte>())
        {
        }

        private protected KerberosEncryptedData(KerberosEncryptionType type, 
            int? key_version, byte[] cipher_text)
        {
            EncryptionType = type;
            KeyVersion = key_version;
            CipherText = cipher_text;
        }
        #endregion

        #region Internal Members
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

        internal bool Decrypt(KerberosKeySet keyset, string realm, KerberosPrincipalName server_name, KerberosKeyUsage key_usage, out byte[] decrypted, out KerberosAuthenticationKey used_key)
        {
            used_key = null;
            if (EncryptionType == KerberosEncryptionType.NULL)
            {
                decrypted = (byte[])CipherText.Clone();
                return true;
            }

            KerberosAuthenticationKey key = keyset.FindKey(EncryptionType, server_name.NameType, server_name.GetPrincipal(realm), KeyVersion ?? 0);
            if (key != null)
            {
                if (key.TryDecrypt(CipherText, key_usage, out decrypted))
                {
                    used_key = key;
                    return true;
                }
            }
            foreach (var next in keyset.GetKeysForEncryption(EncryptionType))
            {
                if (next.TryDecrypt(CipherText, key_usage, out decrypted))
                {
                    used_key = next;
                    return true;
                }
            }
            decrypted = null;
            return false;
        }

        internal static KerberosEncryptedData Parse(DERValue value, byte[] data)
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

        void IDERObject.Write(DERBuilder builder)
        {
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, b => b.WriteInt32((int)EncryptionType));
                if (KeyVersion.HasValue)
                {
                    seq.WriteContextSpecific(1, b => b.WriteInt32(KeyVersion.Value));
                }
                seq.WriteContextSpecific(2, b => b.WriteOctetString(CipherText));
            }
        }
        #endregion
    }
}
