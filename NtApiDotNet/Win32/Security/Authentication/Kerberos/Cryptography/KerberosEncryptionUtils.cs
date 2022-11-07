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
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Cryptography
{
    internal static class KerberosEncryptionUtils
    {
        public const int MD5_CHECKSUM_SIZE = 16;
        public const int AES_CHECKSUM_SIZE = 12;

        public static byte[] DeriveAesKey(byte[] base_key, byte[] folded_key)
        {
            Aes encrypt = new AesManaged();
            encrypt.Mode = CipherMode.ECB;

            folded_key = folded_key.CloneBytes();

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

        public static byte[] DeriveTempKey(KerberosKeyUsage key_usage, byte key_type)
        {
            byte[] r = BitConverter.GetBytes((int)key_usage).Reverse().ToArray();
            Array.Resize(ref r, 5);
            r[4] = key_type;
            return NFold.Compute(r, 16);
        }

        public static string MakeSalt(KerberosPrincipalName name, string realm)
        {
            return MakeSalt(name.Names, realm);
        }

        public static string MakeSalt(IEnumerable<string> names, string realm)
        {
            if (names is null)
            {
                throw new ArgumentNullException(nameof(names));
            }

            if (realm is null)
            {
                throw new ArgumentNullException(nameof(realm));
            }

            return realm.ToUpper() + string.Join("", names);
        }
    }
}
