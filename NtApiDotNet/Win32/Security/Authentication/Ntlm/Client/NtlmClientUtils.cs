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
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.Ntlm.Client
{
    internal static class NtlmClientUtils
    {
        private static readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

        public static byte[] GenerateRandomValue(int length)
        {
            byte[] ret = new byte[length];
            _rng.GetBytes(ret);
            return ret;
        }

        private static byte[] GetKey(byte[] session_key, int key_length, string mode)
        {
            MemoryStream stm = new MemoryStream();
            stm.Write(session_key, 0, key_length);
            byte[] mode_bytes = Encoding.ASCII.GetBytes($"session key to {mode} key magic constant");
            stm.Write(mode_bytes, 0, mode_bytes.Length);
            return MD5.Create().ComputeHash(stm.ToArray());
        }

        public static byte[] CalculateHMACMD5(byte[] key, byte[] data)
        {
            return new HMACMD5(key).ComputeHash(data);
        }

        public static byte[] GetSignKey(NtlmNegotiateFlags negflags, byte[] session_key, bool client)
        {
            if (!negflags.HasFlagSet(NtlmNegotiateFlags.ExtendedSessionSecurity))
                return new byte[0];

            if (client)
            {
                return GetKey(session_key, session_key.Length, "client-to-server signing");
            }
            return GetKey(session_key, session_key.Length, "server-to-client signing");
        }

        public static byte[] GetSealKey(NtlmNegotiateFlags negflags, byte[] session_key, bool client)
        {
            if (negflags.HasFlagSet(NtlmNegotiateFlags.ExtendedSessionSecurity))
            {
                int length = 5;
                if (negflags.HasFlagSet(NtlmNegotiateFlags.Key128Bit))
                {
                    length = session_key.Length;
                }
                else if (negflags.HasFlagSet(NtlmNegotiateFlags.Key56Bit))
                {
                    length = 7;
                }
                if (client)
                {
                    return GetKey(session_key, length, "client-to-server sealing");
                }
                return GetKey(session_key, length, "server-to-client sealing");
            }
            return session_key;
        }

        public static byte[] ConcatBytes(this byte[] a, params byte[][] b)
        {
            MemoryStream stm = new MemoryStream();
            stm.Write(a, 0, a.Length);
            foreach (var x in b)
            {
                stm.Write(x, 0, x.Length);
            }
            return stm.ToArray();
        }

        public static Version GetVersion()
        {
            var ret = Environment.OSVersion.Version;
            return new Version(ret.Major, ret.Minor, ret.Build, 0xF);
        }
    }
}
