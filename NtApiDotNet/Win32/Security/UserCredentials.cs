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

using System;
using System.Runtime.InteropServices;
using System.Security;

namespace NtApiDotNet.Win32.Security
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
        /// The password.
        /// </summary>
        public string Password
        {
            get
            {
                if (SecurePassword == null)
                {
                    return null;
                }

                IntPtr ptr = Marshal.SecureStringToBSTR(SecurePassword);
                try
                {
                    return Marshal.PtrToStringBSTR(ptr);
                }
                finally
                {
                    Marshal.ZeroFreeBSTR(ptr);
                }
            }
            set
            {
                if (value == null)
                {
                    SecurePassword = null;
                }
                else
                {
                    var s = new SecureString();
                    foreach (char c in value)
                    {
                        s.AppendChar(c);
                    }
                    SecurePassword = s;
                }
            }
        }

        /// <summary>
        /// The password as a secure string.
        /// </summary>
        public SecureString SecurePassword { get; set; }

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
            SecurePassword = password;
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
            Password = password;
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
                    return new SafeStructureInOutBuffer<SEC_WINNT_AUTH_IDENTITY_EX>(new SEC_WINNT_AUTH_IDENTITY_EX(UserName, Domain, SecurePassword, list));
                default:
                    throw new ArgumentException($"Unknown credential type for package {package}");
            }
        }
    }
}
