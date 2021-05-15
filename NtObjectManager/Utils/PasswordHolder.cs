//  Copyright 2021 Google Inc. All Rights Reserved.
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
using System.Security;

namespace NtObjectManager.Utils
{
    /// <summary>
    /// <para type="description">Class to hold a password from the user.</para>
    /// </summary>
    public sealed class PasswordHolder
    {
        /// <summary>
        /// Get the password as a secure string.
        /// </summary>
        public SecureString Password { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="str">The secure string password.</param>
        public PasswordHolder(SecureString str)
        {
            Password = str ?? throw new ArgumentNullException(nameof(str));
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="str">The string password.</param>
        public PasswordHolder(string str)
        {
            if (str is null)
            {
                throw new ArgumentNullException(nameof(str));
            }

            SecureString secure_str = new SecureString();
            foreach (var ch in str)
            {
                secure_str.AppendChar(ch);
            }
            Password = secure_str;
        }
    }
}
