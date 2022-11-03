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

using NtApiDotNet.Win32.Security.Authentication.Kerberos;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Credential.AuthIdentity
{
    /// <summary>
    /// A base class to represent a SEC_WINNT_AUTH_PACKED_CREDENTIALS structure.
    /// </summary>
    public abstract class SecWinNtAuthPackedCredential
    {
        /// <summary>
        /// The packed credentials structure.
        /// </summary>
        protected readonly byte[] _credentials;

        /// <summary>
        /// The type of packed credentials.
        /// </summary>
        public Guid CredType { get; }

        /// <summary>
        /// Convert the packed credentials to an array.
        /// </summary>
        /// <returns>The packed credentials.</returns>
        public byte[] ToArray()
        {
            return ToArray(false);
        }

        /// <summary>
        /// Try and parse a packed credential buffer.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <param name="packed_credential">The packed credential.</param>
        /// <returns>True if the packed credential was valid.</returns>
        public static bool TryParse(byte[] data, out SecWinNtAuthPackedCredential packed_credential)
        {
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            packed_credential = null;
            if (data.Length < Marshal.SizeOf(typeof(SEC_WINNT_AUTH_PACKED_CREDENTIALS)))
                return false;

            using (var buffer = data.ToBuffer())
            {
                var cred = buffer.Read<SEC_WINNT_AUTH_PACKED_CREDENTIALS>(0);
                byte[] cred_data = cred.AuthData.CredData.ReadBytes(buffer);
                if (cred.AuthData.CredType == SecWinNtPackedCredentialTypes.Password)
                {
                    packed_credential = new SecWinNtAuthPackedCredentialPassword(cred_data);
                }
                else if (cred.AuthData.CredType == SecWinNtPackedCredentialTypes.KeyTab &&
                    KerberosUtils.TryReadKeyTabFile(cred_data, out IEnumerable<KerberosAuthenticationKey> keys))
                {
                    packed_credential = new SecWinNtAuthPackedCredentialKeyTab(cred_data, keys);
                }
                else
                {
                    packed_credential = new SecWinNtAuthPackedCredentialUnknown(cred.AuthData.CredType, cred_data);
                }
                return true;
            }
        }

        /// <summary>
        /// Parse a packed credential buffer.
        /// </summary>
        /// <param name="data">The data to parse.</param>
        /// <returns>The packed credential.</returns>
        public static SecWinNtAuthPackedCredential Parse(byte[] data)
        {
            if (!TryParse(data, out SecWinNtAuthPackedCredential packed_credential))
                throw new InvalidDataException("Invalid packed credential data.");
            return packed_credential;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="cred_type">The type of packed credentials.</param>
        /// <param name="credentials">The packed credentials structure.</param>
        protected SecWinNtAuthPackedCredential(Guid cred_type, byte[] credentials)
        {
            CredType = cred_type;
            _credentials = credentials ?? throw new ArgumentNullException(nameof(credentials));
        }

        internal byte[] ToArray(bool pad_for_encryption)
        {
            ushort header_size = (ushort)Marshal.SizeOf<SEC_WINNT_AUTH_PACKED_CREDENTIALS>();
            int total_size = header_size + _credentials.Length;
            if ((total_size & 0x7) != 0)
                total_size += 8 - (total_size & 0x7);
            if (pad_for_encryption)
                total_size += 8;

            int padding = total_size - header_size - _credentials.Length;

            SEC_WINNT_AUTH_PACKED_CREDENTIALS packed = new SEC_WINNT_AUTH_PACKED_CREDENTIALS
            {
                cbHeaderLength = header_size,
                cbStructureLength = (ushort)(header_size + _credentials.Length),
                AuthData = new SEC_WINNT_AUTH_DATA
                {
                    CredType = CredType,
                    CredData = new SEC_WINNT_AUTH_BYTE_VECTOR
                    {
                        ByteArrayLength = (ushort)_credentials.Length,
                        ByteArrayOffset = header_size
                    }
                }
            };

            using (var buffer = packed.ToBuffer(_credentials.Length + padding, true))
            {
                buffer.Data.ZeroBuffer();
                buffer.Data.WriteBytes(_credentials);
                return buffer.ToArray();
            }
        }

    }
}
