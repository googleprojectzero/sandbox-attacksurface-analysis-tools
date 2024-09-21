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

using NtApiDotNet.Win32.SafeHandles;
using NtApiDotNet.Win32.Security.Native;

namespace NtApiDotNet.Win32.Security.Credential.AuthIdentity
{
    /// <summary>
    /// Class to represent the auth identity encoded as string.
    /// </summary>
    public sealed class SecWinNtAuthIdentityStrings
    {
        /// <summary>
        /// The user name.
        /// </summary>
        public string UserName { get; }

        /// <summary>
        /// The domain name.
        /// </summary>
        public string Domain { get; }

        /// <summary>
        /// The packed credentials.
        /// </summary>
        public string PackedCredentials { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="username">The user name.</param>
        /// <param name="domain">The domain name.</param>
        /// <param name="packed_credentials">The packed credentials.</param>
        public SecWinNtAuthIdentityStrings(string username, string domain, string packed_credentials)
        {
            UserName = username;
            Domain = domain;
            PackedCredentials = packed_credentials;
        }

        /// <summary>
        /// Create an auth identity from these credentials.
        /// </summary>
        /// <returns>The auth identity credential.</returns>
        public SecWinNtAuthIdentity Create()
        {
            SecurityNativeMethods.SspiEncodeStringsAsAuthIdentity(UserName, Domain,
                PackedCredentials, out SafeSecWinNtAuthIdentityBuffer auth_id).CheckResult();
            return new SecWinNtAuthIdentity(auth_id);
        }

        internal SecWinNtAuthIdentityStrings(SafeSecWinNtAuthIdentityBuffer auth_id)
        {
            SecurityNativeMethods.SspiEncodeAuthIdentityAsStrings(auth_id, out SafeLocalAllocBuffer username,
               out SafeLocalAllocBuffer domain, out SafeLocalAllocBuffer packed_credentials).CheckResult();
            using (var list = new DisposableList(new[] { username, domain, packed_credentials }))
            {
                UserName = username.ReadNulTerminatedUnicodeStringUnsafe();
                Domain = domain.ReadNulTerminatedUnicodeStringUnsafe();
                PackedCredentials = packed_credentials.ReadNulTerminatedUnicodeStringUnsafe();
            }
        }
    }
}
