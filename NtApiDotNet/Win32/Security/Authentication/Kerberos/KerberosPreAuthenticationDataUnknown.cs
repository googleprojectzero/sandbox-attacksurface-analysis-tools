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

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos
{
    /// <summary>
    /// Class to represent an unknown PA-DATA value.
    /// </summary>
    public sealed class KerberosPreAuthenticationDataUnknown : KerberosPreAuthenticationData
    {
        /// <summary>
        /// The pre-authentication data.
        /// </summary>
        public byte[] Data { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="type">The type of pre-authentication data.</param>
        /// <param name="data">The data for the preauthentication.</param>
        public KerberosPreAuthenticationDataUnknown(KerberosPreAuthenticationType type, byte[] data) : base(type)
        {
            Data = data.CloneBytes();
        }

        private protected override byte[] GetData()
        {
            return Data;
        }
    }
}
