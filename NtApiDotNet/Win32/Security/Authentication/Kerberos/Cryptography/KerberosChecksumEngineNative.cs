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
    internal class KerberosChecksumEngineNative : KerberosChecksumEngine
    {
        private readonly KERB_CHECKSUM _engine;

        private KerberosChecksumEngineNative(KERB_CHECKSUM engine) : base(engine.Type, engine.Size)
        {
            _engine = engine;
        }

        public override byte[] ComputeHash(byte[] key, byte[] data, int offset, int length, KerberosKeyUsage key_usage)
        {
            _engine.InitializeEx(key, key.Length, key_usage, out IntPtr context).ToNtException();
            try
            {
                byte[] data_to_hash = data;
                if (offset != 0 || data.Length != length)
                {
                    data_to_hash = new byte[length];
                    Buffer.BlockCopy(data, offset, data_to_hash, 0, length);
                }
                _engine.Sum(context, data_to_hash.Length, data_to_hash).ToNtException();
                byte[] hash = new byte[ChecksumSize];
                _engine.Finalize(context, hash).ToNtException();
                return hash;
            }
            finally
            {
                _engine.Finish(ref context);
            }
        }

        internal static KerberosChecksumEngine GetNative(KerberosChecksumType checksum_type, bool throw_on_unsupported)
        {
            try
            {
                if (SecurityNativeMethods.CDLocateCheckSum(checksum_type, out IntPtr ptr).IsSuccess())
                    return new KerberosChecksumEngineNative(Marshal.PtrToStructure<KERB_CHECKSUM>(ptr));
            }
            catch (EntryPointNotFoundException)
            {
            }
            catch (DllNotFoundException)
            {
            }
            if (throw_on_unsupported)
                throw new ArgumentException("Unsupported checksum algorithm.", nameof(checksum_type));
            return new KerberosChecksumEngineUnsupported(checksum_type);
        }
    }
}
