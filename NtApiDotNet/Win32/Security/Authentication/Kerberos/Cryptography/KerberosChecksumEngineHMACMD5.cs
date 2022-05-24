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
using System.IO;
using System.Security.Cryptography;
using System.Text;
using static NtApiDotNet.Win32.Security.Authentication.Kerberos.Cryptography.KerberosEncryptionUtils;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Cryptography
{
    internal class KerberosChecksumEngineHMACMD5 : KerberosChecksumEngine
    {
        public KerberosChecksumEngineHMACMD5() : base(KerberosChecksumType.HMAC_MD5, MD5_CHECKSUM_SIZE)
        {
        }

        public override byte[] ComputeHash(byte[] key, byte[] data, int offset, int length, KerberosKeyUsage key_usage)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            byte[] sign_key = new HMACMD5(key).ComputeHash(Encoding.ASCII.GetBytes("signaturekey\0"));

            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            writer.Write((int)key_usage);
            writer.Write(data, offset, length);

            byte[] tmp = MD5.Create().ComputeHash(stm.ToArray());
            return new HMACMD5(sign_key).ComputeHash(tmp);
        }
    }
}
