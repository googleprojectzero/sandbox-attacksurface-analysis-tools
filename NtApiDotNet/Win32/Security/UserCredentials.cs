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

namespace NtApiDotNet.Win32.Security
{
    /// <summary>
    /// Class to hold user credentials.
    /// </summary>
    public class UserCredentials
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
        public string Password { get; set; }

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
            : this(username, domain, null)
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

        internal SEC_WINNT_AUTH_IDENTITY_EX GetAuthIdentity() => new SEC_WINNT_AUTH_IDENTITY_EX(UserName, Domain, Password);
    }
}
