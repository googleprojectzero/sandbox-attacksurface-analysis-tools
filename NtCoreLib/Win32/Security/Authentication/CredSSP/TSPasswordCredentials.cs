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
using System;
using System.Text;

namespace NtApiDotNet.Win32.Security.Authentication.CredSSP
{
    /// <summary>
    /// Class to represent a TSPasswordCreds structure.
    /// </summary>
    public sealed class TSPasswordCredentials : TSCredentials
    {
        private readonly byte[] _password;

        /// <summary>
        /// Constructor.
        /// </summary>
        public TSPasswordCredentials(string username, string domain, byte[] password) : base(TSCredentialsType.Password)
        {
            UserName = username ?? throw new ArgumentNullException(nameof(username));
            Domain = domain ?? throw new ArgumentNullException(nameof(domain));
            _password = password ?? throw new ArgumentNullException(nameof(password));
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public TSPasswordCredentials(string username, string domain, string password) 
            : this(username, domain, Encoding.Unicode.GetBytes(password))
        {
        }

        /// <summary>
        /// The domain name.
        /// </summary>
        public string Domain { get; }

        /// <summary>
        /// The user name.
        /// </summary>
        public string UserName { get; }

        /// <summary>
        /// The password.
        /// </summary>
        public string Password => Encoding.Unicode.GetString(_password);

        private protected override byte[] GetCredentials()
        {
            DERBuilder builder = new DERBuilder();
            using (var seq = builder.CreateSequence())
            {
                seq.WriteContextSpecific(0, Encoding.Unicode.GetBytes(Domain));
                seq.WriteContextSpecific(1, Encoding.Unicode.GetBytes(UserName));
                seq.WriteContextSpecific(2, _password);
            }
            return builder.ToArray();
        }
    }
}
