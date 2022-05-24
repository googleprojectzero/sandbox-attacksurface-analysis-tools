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

using System.Linq;
using System.Security.Cryptography;
using static NtApiDotNet.Win32.Security.Authentication.Kerberos.Cryptography.KerberosEncryptionUtils;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Cryptography
{
    internal class KerberosChecksumEngineAESSHA196 : KerberosChecksumEngine
    {
        private const byte SignatureKey = 0x99;

        private KerberosChecksumEngineAESSHA196(KerberosChecksumType checksum_type) 
            : base(checksum_type, AES_CHECKSUM_SIZE)
        {
        }

        public override byte[] ComputeHash(byte[] key, byte[] data, int offset, int length, KerberosKeyUsage key_usage)
        {
            byte[] derive_mac_key = DeriveTempKey(key_usage, SignatureKey);
            return new HMACSHA1(DeriveAesKey(key, derive_mac_key)).ComputeHash(data,
                offset, length).Take(AES_CHECKSUM_SIZE).ToArray();
        }

        public static KerberosChecksumEngine AES128 = new KerberosChecksumEngineAESSHA196(KerberosChecksumType.HMAC_SHA1_96_AES_128);
        public static KerberosChecksumEngine AES256 = new KerberosChecksumEngineAESSHA196(KerberosChecksumType.HMAC_SHA1_96_AES_256);
    }
}
