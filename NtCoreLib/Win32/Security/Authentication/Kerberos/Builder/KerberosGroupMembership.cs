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

using NtApiDotNet.Ndr.Marshal;
using NtApiDotNet.Win32.Security.Authentication.Kerberos.Ndr;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder
{
    /// <summary>
    /// A kerberos group membership.
    /// </summary>
    public class KerberosGroupMembership
    {
        /// <summary>
        /// The group SID's relative ID.
        /// </summary>
        public uint RelativeId { get; set; }
        /// <summary>
        /// The group's attributes.
        /// </summary>
        public GroupAttributes Attributes { get; set; }

        internal static List<KerberosGroupMembership> CreateGroup(NdrEmbeddedPointer<GROUP_MEMBERSHIP_DEVICE[]> ptr)
        {
            if (ptr == null)
                return null;
            return ptr.GetValue().Select(Create).ToList();
        }

        internal static List<KerberosGroupMembership> CreateGroup(NdrEmbeddedPointer<GROUP_MEMBERSHIP[]> ptr)
        {
            if (ptr == null)
                return null;
            return ptr.GetValue().Select(Create).ToList();
        }

        internal static NdrEmbeddedPointer<GROUP_MEMBERSHIP[]> FromGroup(IList<KerberosGroupMembership> groups, ref int count)
        {
            count = groups?.Count ?? 0;
            if (groups != null)
            {
                return groups.Select(ToStruct).ToArray();
            }
            return null;
        }

        internal static NdrEmbeddedPointer<GROUP_MEMBERSHIP_DEVICE[]> FromGroupDevice(IList<KerberosGroupMembership> groups, ref int count)
        {
            count = groups?.Count ?? 0;
            if (groups != null)
            {
                return groups.Select(ToStructDevice).ToArray();
            }
            return null;
        }

        private static KerberosGroupMembership Create(GROUP_MEMBERSHIP s)
        {
            return new KerberosGroupMembership()
            {
                RelativeId = (uint)s.RelativeId,
                Attributes = (GroupAttributes)s.Attributes
            };
        }

        private static KerberosGroupMembership Create(GROUP_MEMBERSHIP_DEVICE s)
        {
            return new KerberosGroupMembership()
            {
                RelativeId = (uint)s.RelativeId,
                Attributes = (GroupAttributes)s.Attributes
            };
        }

        private static GROUP_MEMBERSHIP ToStruct(KerberosGroupMembership s)
        {
            if (s is null)
            {
                throw new ArgumentNullException(nameof(s));
            }

            return new GROUP_MEMBERSHIP()
            {
                RelativeId = (int)s.RelativeId,
                Attributes = (int)s.Attributes
            };
        }

        private static GROUP_MEMBERSHIP_DEVICE ToStructDevice(KerberosGroupMembership s)
        {
            if (s is null)
            {
                throw new ArgumentNullException(nameof(s));
            }

            return new GROUP_MEMBERSHIP_DEVICE()
            {
                RelativeId = (int)s.RelativeId,
                Attributes = (int)s.Attributes
            };
        }
    }
}
