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

namespace NtApiDotNet.Win32.DirectoryService
{
    /// <summary>
    /// Class to represent a security principal in the directory.
    /// </summary>
    public sealed class DirectoryServiceSecurityPrincipal
    {
        /// <summary>
        /// Distinguished name of the group.
        /// </summary>
        public string DistinguishedName { get; }

        /// <summary>
        /// The SID of the object.
        /// </summary>
        public Sid Sid { get; }

        /// <summary>
        /// Overridden Equals.
        /// </summary>
        /// <param name="obj">The other object to test.</param>
        /// <returns>True if equal.</returns>
        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;
            if (!(obj is DirectoryServiceSecurityPrincipal prin))
            {
                return false;
            }

            return DistinguishedName == prin.DistinguishedName && Sid.Equals(prin.Sid);
        }

        /// <summary>
        /// Overridden GetHashCode.
        /// </summary>
        /// <returns>The hash code.</returns>
        public override int GetHashCode()
        {
            return DistinguishedName.GetHashCode() ^ Sid.GetHashCode();
        }

        internal DirectoryServiceSecurityPrincipal(string dn, Sid sid)
        {
            DistinguishedName = dn;
            Sid = sid;
        }
    }
}
