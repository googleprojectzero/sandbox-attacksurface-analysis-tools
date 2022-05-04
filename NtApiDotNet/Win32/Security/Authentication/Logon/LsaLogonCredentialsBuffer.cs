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

using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authentication.Logon
{
    /// <summary>
    /// Class to represent a raw LSA logon credentials buffer.
    /// </summary>
    public class LsaLogonCredentialsBuffer : ILsaLogonCredentials, ILsaLogonCredentialsSerializable
    {
        private readonly byte[] _data;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="data">The credentials as a byte array.</param>
        public LsaLogonCredentialsBuffer(byte[] data)
        {
            _data = (byte[])data.Clone();
        }

        /// <summary>
        /// The credentials data.
        /// </summary>
        public byte[] Data => (byte[])_data.Clone();

        byte[] ILsaLogonCredentialsSerializable.ToArray()
        {
            return Data;
        }

        SafeBuffer ILsaLogonCredentials.ToBuffer(DisposableList list)
        {
            return _data.ToBuffer();
        }
    }
}
