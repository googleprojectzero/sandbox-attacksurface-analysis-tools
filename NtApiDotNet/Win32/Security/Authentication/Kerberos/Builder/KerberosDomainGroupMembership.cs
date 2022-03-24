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
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Builder
{
    /// <summary>
    /// Structure
    /// </summary>
    public sealed class KerberosDomainGroupMembership
    {
        /// <summary>
        /// The domain ID SID.
        /// </summary>
        public Sid DomainId { get; set; }

        /// <summary>
        /// The list of membership groups.
        /// </summary>
        public List<KerberosGroupMembership> GroupIds { get; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public KerberosDomainGroupMembership()
        {
            GroupIds = new List<KerberosGroupMembership>();
        }

        private KerberosDomainGroupMembership(DOMAIN_GROUP_MEMBERSHIP group) : this()
        {
            DomainId = group.DomainId.GetValue().ToSid();
            GroupIds.AddRange(KerberosGroupMembership.CreateGroup(group.GroupIds) ?? new List<KerberosGroupMembership>());
        }

        internal static List<KerberosDomainGroupMembership> FromGroup(NdrEmbeddedPointer<DOMAIN_GROUP_MEMBERSHIP[]> groups)
        {
            if (groups == null)
                return null;
            return groups.GetValue().Select(g => new KerberosDomainGroupMembership(g)).ToList();
        }

        private static DOMAIN_GROUP_MEMBERSHIP ToStruct(KerberosDomainGroupMembership group)
        {
            DOMAIN_GROUP_MEMBERSHIP ret = new DOMAIN_GROUP_MEMBERSHIP();
            ret.DomainId = new RPC_SID_DEVICE(group.DomainId);
            ret.GroupIds = KerberosGroupMembership.FromGroupDevice(group.GroupIds, ref ret.GroupCount);
            return ret;
        }

        internal static NdrEmbeddedPointer<DOMAIN_GROUP_MEMBERSHIP[]> FromGroup(IList<KerberosDomainGroupMembership> groups, ref int count)
        {
            count = groups?.Count ?? 0;
            if (groups != null)
            {
                return groups.Select(ToStruct).ToArray();
            }
            return null;
        }
    }
}
