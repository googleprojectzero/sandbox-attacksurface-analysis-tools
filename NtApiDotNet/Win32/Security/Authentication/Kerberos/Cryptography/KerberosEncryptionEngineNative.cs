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

using NtApiDotNet.Win32.Security.Native;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Cryptography
{
    internal class KerberosEncryptionEngineNative : KerberosEncryptionEngine
    {
        private readonly KERB_ECRYPT _engine;

        private KerberosEncryptionEngineNative(KERB_ECRYPT engine)
            : base(engine.Type, engine.ChecksumType, KerberosChecksumEngine.Get(engine.ChecksumType, false).ChecksumSize,
                  engine.AdditionalEncryptionSize, engine.BlockSize, engine.KeySize, engine.AlgName)
        {
            _engine = engine;
        }

        public override byte[] DeriveKey(string password, int iterations, string salt)
        {
            switch (EncryptionType)
            {
                case KerberosEncryptionType.DES_CBC_MD5:
                case KerberosEncryptionType.DES_CBC_NONE:
                case KerberosEncryptionType.DES_CBC_CRC:
                    password += salt;
                    break;
            }

            byte[] key = new byte[_engine.KeySize];
            _engine.HashPassword(new UnicodeString(password), new UnicodeString(salt), iterations, key).ToNtException();
            return key;
        }

        public override byte[] GenerateKey()
        {
            byte[] key = new byte[_engine.KeySize];
            _engine.RandomKey(null, 0, key).ToNtException();
            return key;
        }

        public override byte[] Encrypt(byte[] key, byte[] plain_text, KerberosKeyUsage key_usage)
        {
            _engine.Initialize(key, key.Length, key_usage, out IntPtr context).ToNtException();
            try
            {
                int output_size = plain_text.Length;
                int remainder = output_size % BlockSize;
                if (remainder != 0)
                    output_size += BlockSize - remainder;
                output_size += AdditionalEncryptionSize;
                byte[] output = new byte[output_size];
                _engine.Encrypt(context, plain_text, plain_text.Length, output, ref output_size).ToNtException();
                Array.Resize(ref output, output_size);
                return output;
            }
            finally
            {
                _engine.Finish(ref context);
            }
        }

        public override bool TryDecrypt(byte[] key, byte[] cipher_text, KerberosKeyUsage key_usage, out byte[] plain_text)
        {
            plain_text = null;
            _engine.Initialize(key, key.Length, key_usage, out IntPtr context).ToNtException();
            try
            {
                int output_size = cipher_text.Length;
                plain_text = new byte[output_size];
                if (!_engine.Decrypt(context, cipher_text, cipher_text.Length, plain_text, ref output_size).IsSuccess())
                    return false;
                Array.Resize(ref plain_text, output_size);
                return true;
            }
            finally
            {
                _engine.Finish(ref context);
            }
        }

        internal static KerberosEncryptionEngine GetNative(KerberosEncryptionType encryption_type, bool throw_on_unsupported)
        {
            try
            {
                if (SecurityNativeMethods.CDLocateCSystem(encryption_type, out IntPtr ptr).IsSuccess())
                    return new KerberosEncryptionEngineNative(Marshal.PtrToStructure<KERB_ECRYPT>(ptr));
            }
            catch (EntryPointNotFoundException)
            {
            }
            catch (DllNotFoundException)
            {
            }
            if (throw_on_unsupported)
                throw new ArgumentException("Unsupported encryption algorithm.", nameof(encryption_type));
            return new KerberosEncryptionEngineUnsupported(encryption_type);
        }

        internal static KerberosEncryptionType[] GetSupportedTypes()
        {
            try
            {
                // Refresh the enabled types.
                SecurityNativeMethods.CDGetIntegrityVect(out uint _);

                int count = 0;
                if (!SecurityNativeMethods.CDBuildIntegrityVect(ref count, null).IsSuccess())
                    return new KerberosEncryptionType[0];
                var ret = new KerberosEncryptionType[count];
                if (!SecurityNativeMethods.CDBuildIntegrityVect(ref count, ret).IsSuccess())
                    return new KerberosEncryptionType[0];
                return ret;
            }
            catch (EntryPointNotFoundException)
            {
            }
            catch (DllNotFoundException)
            {
            }
            return new KerberosEncryptionType[0];
        }

        internal static KerberosEncryptionType[] GetAllTypes()
        {
            try
            {
                if (!SecurityNativeMethods.CDBuildVect(out int count, null).IsSuccess())
                    return new KerberosEncryptionType[0];
                var ret = new KerberosEncryptionType[count];
                if (!SecurityNativeMethods.CDBuildVect(out count, ret).IsSuccess())
                    return new KerberosEncryptionType[0];
                return ret;
            }
            catch (EntryPointNotFoundException)
            {
            }
            catch (DllNotFoundException)
            {
            }
            return new KerberosEncryptionType[0];
        }
    }
}
