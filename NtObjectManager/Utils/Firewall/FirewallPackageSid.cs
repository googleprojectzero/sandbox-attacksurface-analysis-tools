//  Copyright 2021 Google LLC. All Rights Reserved.
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

using NtApiDotNet;
using NtApiDotNet.Win32;

namespace NtObjectManager.Utils.Firewall
{
    /// <summary>
    /// Helper class to get a firewall package SID.
    /// </summary>
    public class FirewallPackageSid
    {
        /// <summary>
        /// The package SID.
        /// </summary>
        public Sid Sid { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="sid">The SID in SDDL format or a package name.</param>
        public FirewallPackageSid(string sid)
        {
            Sid = Sid.Parse(sid, false).GetResultOrDefault();
            if (Sid == null)
            {
                Sid = TokenUtils.GetPackageSidFromName(sid);
            }
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="token">The token to extract the package SID from.</param>
        public FirewallPackageSid(NtToken token)
        {
            if (token.AppContainer)
            {
                Sid = token.AppContainerSid;
            }
            else
            {
                Sid = KnownSids.Null;
            }
        }
    }
}
