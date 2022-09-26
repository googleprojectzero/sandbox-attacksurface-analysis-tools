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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Cryptography
{
    internal class KerberosEncryptionEngineUnsupported : KerberosEncryptionEngine
    {
        public KerberosEncryptionEngineUnsupported(KerberosEncryptionType encryption_type) 
            : base(encryption_type, 0, 0, 0, 0, 0, null)
        {
        }

        public override byte[] DeriveKey(string password, int iterations, string salt)
        {
            throw new NotImplementedException();
        }

        public override byte[] Encrypt(byte[] key, byte[] plain_text, KerberosKeyUsage key_usage)
        {
            throw new NotImplementedException();
        }

        public override bool TryDecrypt(byte[] key, byte[] cipher_text, KerberosKeyUsage key_usage, out byte[] plain_text)
        {
            throw new NotImplementedException();
        }
    }
}
