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

using NtApiDotNet.Win32.SafeHandles;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Runtime.InteropServices;
using System.Security;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Class to hold user credentials.
    /// </summary>
    public sealed class UserCredentials : AuthenticationCredentials, IDisposable
    {
        #region Public Properties
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
        /// If using Kerberos this indicates that no PAC should be included in the TGT.
        /// </summary>
        public bool IdentityOnly { get; set; }
        /// <summary>
        /// If using negotiate specify the list of packages to use. For example specifying !ntlm disabled NTLM.
        /// </summary>
        public string PackageList { get; set; }
        #endregion

        #region Constructors
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
        #endregion

        #region Public Methods
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
        /// Convert the authentication credentials to a marshalled byte array.
        /// </summary>
        /// <returns>The credentials as a byte array.</returns>
        public byte[] ToArray()
        {
            using (var list = new DisposableList())
            {
                var auth_id = list.AddResource(ToAuthIdentityEx(list).ToBuffer());
                SecurityNativeMethods.SspiMarshalAuthIdentity(auth_id, out int length, out SafeLocalAllocBuffer buffer).CheckResult();
                list.AddResource(buffer);
                buffer.Initialize((ulong)length);
                return BufferUtils.ReadBytes(buffer, 0, length);
            }
        }

        /// <summary>
        /// Dispose method.
        /// </summary>
        public void Dispose()
        {
            Password?.Dispose();
        }
        #endregion

        #region Internal Methods
        internal SecureStringMarshalBuffer GetPassword()
        {
            if (Password != null)
            {
                return new SecureStringMarshalBuffer(Password);
            }
            return new SecureStringMarshalBuffer();
        }

        internal byte[] GetPasswordBytes()
        {
            if (Password == null)
                return new byte[0];
            using (var buffer = GetPassword())
            {
                byte[] ret = new byte[Password.Length * 2];
                Marshal.Copy(buffer.Ptr, ret, 0, ret.Length);
                return ret;
            }
        }

        internal SEC_WINNT_AUTH_IDENTITY ToAuthIdentity(DisposableList list)
        {
            var auth_id = new SEC_WINNT_AUTH_IDENTITY(UserName, Domain, Password, list);
            if (IdentityOnly)
                auth_id.Flags |= SecWinNtAuthIdentityFlags.IdentityOnly;
            return auth_id;
        }

        internal SEC_WINNT_AUTH_IDENTITY_EX ToAuthIdentityEx(DisposableList list)
        {
            var auth_id = new SEC_WINNT_AUTH_IDENTITY_EX(UserName, Domain, Password, PackageList, list);
            if (IdentityOnly)
                auth_id.Flags |= SecWinNtAuthIdentityFlags.IdentityOnly;
            return auth_id;
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
                case "kerberos":
                case "wdigest":
                    return ToAuthIdentity(list).ToBuffer();
                case "negotiate":
                case "tsssp":
                    if (string.IsNullOrWhiteSpace(PackageList))
                    {
                        return ToAuthIdentity(list).ToBuffer();
                    }
                    else
                    {
                        return ToAuthIdentityEx(list).ToBuffer();
                    }
                case "credssp":
                    return new KERB_INTERACTIVE_LOGON(UserName, Domain, Password, list).ToBuffer();
                default:
                    throw new ArgumentException($"Unknown credential type for package {package}");
            }
        }
        #endregion
    }
}
