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

using NtApiDotNet.Win32.Security.Authentication.Kerberos.Ndr;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder
{
    /// <summary>
    /// A kerberos group membership.
    /// </summary>
    public struct KerberosGroupMembership
    {
        /// <summary>
        /// The group SID's relative ID.
        /// </summary>
        public uint RelativeId;
        /// <summary>
        /// The group's attributes.
        /// </summary>
        public GroupAttributes Attributes;

        internal static KerberosGroupMembership Create(GROUP_MEMBERSHIP s)
        {
            return new KerberosGroupMembership()
            {
                RelativeId = (uint)s.RelativeId,
                Attributes = (GroupAttributes)s.Attributes
            };
        }

        internal static GROUP_MEMBERSHIP ToStruct(KerberosGroupMembership s)
        {
            return new GROUP_MEMBERSHIP()
            {
                RelativeId = (int)s.RelativeId,
                Attributes = (int)s.Attributes
            };
        }
    }
}
