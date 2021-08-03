//  Copyright 2021 Google LLC. All Rights Reserved.
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

using NtApiDotNet.Utilities.Memory;
using System;

namespace NtApiDotNet.Net.Firewall
{
    /// <summary>
    /// Base security association class.
    /// </summary>
    public class IPsecSecurityAssociationParameter
    {
        /// <summary>
        /// Index of the security parameter (SPI).
        /// </summary>
        public uint Index { get; }

        /// <summary>
        /// Transform type.
        /// </summary>
        public IPsecTransformType TransformType { get; }

        private protected IPsecSecurityAssociationParameter(IPSEC_SA0 sa)
        {
            Index = sa.spi;
            TransformType = sa.saTransformType;
        }

        internal static IPsecSecurityAssociationParameter Create(IPSEC_SA0 sa)
        {
            switch (sa.saTransformType)
            {
                case IPsecTransformType.AH:
                case IPsecTransformType.EspAuth:
                case IPsecTransformType.EspAuthFw:
                    return new IPsecSecurityAssociationAuthInformation(sa);
                case IPsecTransformType.EspCipher:
                    return new IPsecSecurityAssociationCipherInformation(sa);
                case IPsecTransformType.EspAuthAndCipher:
                    return new IPsecSecurityAssociationAuthCipherInformation(sa);
            }
            return new IPsecSecurityAssociationParameter(sa);
        }
    }

    /// <summary>
    /// IPsec SA authentication information.
    /// </summary>
    public sealed class IPsecSecurityAssociationAuthInformation : IPsecSecurityAssociationParameter
    {
        /// <summary>
        /// Type of authentication.
        /// </summary>
        public IPsecAuthType Type { get; }

        /// <summary>
        /// Authentication configuration.
        /// </summary>
        public IPsecAuthConfig Config { get; }

        /// <summary>
        /// Module ID for the crypto.
        /// </summary>
        public Guid? CryptoModuleId { get; }

        /// <summary>
        /// Authentication key.
        /// </summary>
        public byte[] Key { get; }

        internal IPsecSecurityAssociationAuthInformation(IPSEC_SA0 sa) : base(sa)
        {
            var auth_info = sa.ptr.ReadStruct<IPSEC_SA_AUTH_INFORMATION0>();
            Key = auth_info.authKey.ToArray();
            CryptoModuleId = auth_info.authTransform.cryptoModuleId.ReadGuid();
            Type = auth_info.authTransform.authTransformId.authType;
            Config = auth_info.authTransform.authTransformId.authConfig;
        }
    }

    /// <summary>
    /// IPsec SA authentication information.
    /// </summary>
    public sealed class IPsecSecurityAssociationCipherInformation : IPsecSecurityAssociationParameter
    {
        /// <summary>
        /// Type of cipher.
        /// </summary>
        public IPsecCipherType Type { get; }

        /// <summary>
        /// Cipher configuration.
        /// </summary>
        public IPsecCipherConfig Config { get; }

        /// <summary>
        /// Module ID for the crypto.
        /// </summary>
        public Guid? CryptoModuleId { get; }

        /// <summary>
        /// Cipher key.
        /// </summary>
        public byte[] Key { get; }

        internal IPsecSecurityAssociationCipherInformation(IPSEC_SA0 sa) : base(sa)
        {
            var cipher_info = sa.ptr.ReadStruct<IPSEC_SA_CIPHER_INFORMATION0>();
            Key = cipher_info.cipherKey.ToArray();
            CryptoModuleId = cipher_info.cipherTransform.cryptoModuleId.ReadGuid();
            Type = cipher_info.cipherTransform.cipherTransformId.cipherType;
            Config = cipher_info.cipherTransform.cipherTransformId.cipherConfig;
        }
    }

    /// <summary>
    /// IPsec SA authentication information.
    /// </summary>
    public sealed class IPsecSecurityAssociationAuthCipherInformation : IPsecSecurityAssociationParameter
    {
        /// <summary>
        /// Type of authentication.
        /// </summary>
        public IPsecAuthType AuthType { get; }

        /// <summary>
        /// Authentication configuration.
        /// </summary>
        public IPsecAuthConfig AuthConfig { get; }

        /// <summary>
        /// Modify ID for the crypto.
        /// </summary>
        public Guid? AuthCryptoModuleId { get; }

        /// <summary>
        /// Authentication key.
        /// </summary>
        public byte[] AuthKey { get; }

        /// <summary>
        /// Type of cipher.
        /// </summary>
        public IPsecCipherType CipherType { get; }

        /// <summary>
        /// Cipher configuration.
        /// </summary>
        public IPsecCipherConfig CipherConfig { get; }

        /// <summary>
        /// Module ID for the crypto.
        /// </summary>
        public Guid? CipherCryptoModuleId { get; }

        /// <summary>
        /// Cipher key.
        /// </summary>
        public byte[] CipherKey { get; }

        internal IPsecSecurityAssociationAuthCipherInformation(IPSEC_SA0 sa) : base(sa)
        {
            var auth_and_cipher_info = sa.ptr.ReadStruct<IPSEC_SA_AUTH_AND_CIPHER_INFORMATION0>();
            var auth_info = auth_and_cipher_info.saAuthInformation;
            AuthKey = auth_info.authKey.ToArray();
            AuthCryptoModuleId = auth_info.authTransform.cryptoModuleId.ReadGuid();
            AuthType = auth_info.authTransform.authTransformId.authType;
            AuthConfig = auth_info.authTransform.authTransformId.authConfig;

            var cipher_info = auth_and_cipher_info.saCipherInformation;
            CipherKey = cipher_info.cipherKey.ToArray();
            CipherCryptoModuleId = cipher_info.cipherTransform.cryptoModuleId.ReadGuid();
            CipherType = cipher_info.cipherTransform.cipherTransformId.cipherType;
            CipherConfig = cipher_info.cipherTransform.cipherTransformId.cipherConfig;
        }
    }
}
