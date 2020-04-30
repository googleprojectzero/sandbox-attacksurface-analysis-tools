//  Copyright 2020 Google Inc. All Rights Reserved.
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
using System.Security;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Class to hold user credentials.
    /// </summary>
    public class UserCredentials : AuthenticationCredentials
    {
        /// <summary>
        /// The user name.
        /// </summary>
        public string UserName { get; set; }
        /// <summary>
        /// The domain.
        /// </summary>
        public string Domain { get; set; }
        /// <summary>
        /// The password as a secure string.
        /// </summary>
        public SecureString Password { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="username">Username.</param>
        /// <param name="domain">Domain name.</param>
        /// <param name="password">Password.</param>
        public UserCredentials(string username, string domain, SecureString password)
        {
            UserName = username;
            Domain = domain;
            Password = password;
        }

        /// <summary>
        /// Set the password as in plain text.
        /// </summary>
        /// <param name="password">The password in plain text.</param>
        public void SetPassword(string password)
        {
            if (password == null)
            {
                Password = null;
            }
            else
            {
                var s = new SecureString();
                foreach (char c in password)
                {
                    s.AppendChar(c);
                }
                Password = s;
            }
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="username">Username.</param>
        /// <param name="domain">Domain name.</param>
        /// <param name="password">Password.</param>
        public UserCredentials(string username, string domain, string password)
        {
            UserName = username;
            Domain = domain;
            SetPassword(password);
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="username">Username.</param>
        /// <param name="domain">Domain name.</param>
        public UserCredentials(string username, string domain)
            : this(username, domain, (SecureString)null)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="username">Username.</param>
        public UserCredentials(string username)
            : this(username, null)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public UserCredentials()
        {
        }

        internal override SafeBuffer ToBuffer(DisposableList list, string package)
        {
            if (package == null)
            {
                throw new ArgumentNullException(nameof(package));
            }
            switch (package.ToLower())
            {
                case "ntlm":
                case "negotiate":
                case "kerberos":
                case "wdigest":
                    return new SafeStructureInOutBuffer<SEC_WINNT_AUTH_IDENTITY>(new SEC_WINNT_AUTH_IDENTITY(UserName, Domain, Password, list));
                default:
                    throw new ArgumentException($"Unknown credential type for package {package}");
            }
        }
    }
}
