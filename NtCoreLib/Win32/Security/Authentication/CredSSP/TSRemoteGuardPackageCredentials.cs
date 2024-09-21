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

using NtApiDotNet.Utilities.ASN1.Builder;
using NtApiDotNet.Win32.Security.Authentication.Logon;
using System;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.CredSSP
{
    /// <summary>
    /// Class to represent a packaged credential for remote guard.
    /// </summary>
    public sealed class TSRemoteGuardPackageCredentials : IDERObject
    {
        /// <summary>
        /// The name of the package the credentials are intended.
        /// </summary>
        public string PackageName { get; }

        /// <summary>
        /// The credentials buffer.
        /// </summary>
        public byte[] CredBuffer { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="package_name">The package name.</param>
        /// <param name="cred_buffer">The credentials buffer.</param>
        /// <exception cref="ArgumentNullException">Thrown if any argument is null.</exception>
        public TSRemoteGuardPackageCredentials(string package_name, byte[] cred_buffer)
        {
            if (package_name is null)
            {
                throw new ArgumentNullException(nameof(package_name));
            }

            if (cred_buffer is null)
            {
                throw new ArgumentNullException(nameof(cred_buffer));
            }

            PackageName = package_name;
            CredBuffer = cred_buffer.CloneBytes();
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="package_name">The package name.</param>
        /// <param name="credentials">The credentials.</param>
        /// <exception cref="ArgumentNullException">Thrown if any argument is null.</exception>
        public TSRemoteGuardPackageCredentials(string package_name, ILsaLogonCredentialsSerializable credentials) 
            : this(package_name, credentials?.ToArray())
        {
        }

        void IDERObject.Write(DERBuilder builder)
        {
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, Encoding.Unicode.GetBytes(PackageName));
                seq.WriteContextSpecific(1, CredBuffer);
            }
        }
    }
}
