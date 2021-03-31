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

using NtApiDotNet.Win32.SafeHandles;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Sam
{
    /// <summary>
    /// Class to represent a SAM domain object.
    /// </summary>
    public sealed class SamDomain : SamObject
    {
        #region Private Members
        private readonly Lazy<string> _name;

        private IReadOnlyList<SidName> MapNames(string[] names, SafeSamMemoryBuffer rid_buffer, SafeSamMemoryBuffer use_buffer)
        {
            using (rid_buffer)
            {
                using (use_buffer)
                {
                    rid_buffer.Initialize<uint>((uint)names.Length);
                    use_buffer.Initialize<int>((uint)names.Length);
                    uint[] rids = rid_buffer.ReadArray<uint>(0, names.Length);
                    int[] use = use_buffer.ReadArray<int>(0, names.Length);

                    return names.Select((n, i) => new SidName(DomainId.CreateRelative(rids[i]),
                            Name, n.ToString(), SidNameSource.Account, (SidNameUse)use[i], false))
                            .Where(n => n.NameUse != SidNameUse.Unknown).ToList().AsReadOnly();
                }
            }
        }

        private IReadOnlyList<SidName> MapIds(uint[] rids, SafeSamMemoryBuffer names_buffer, SafeSamMemoryBuffer use_buffer)
        {
            using (names_buffer)
            {
                using (use_buffer)
                {
                    names_buffer.Initialize<UnicodeStringOut>((uint)rids.Length);
                    use_buffer.Initialize<int>((uint)rids.Length);

                    UnicodeStringOut[] names = names_buffer.ReadArray<UnicodeStringOut>(0, rids.Length);
                    int[] use = use_buffer.ReadArray<int>(0, rids.Length);

                    return names.Select((n, i) => new SidName(DomainId.CreateRelative(rids[i]),
                            Name, n.ToString(), SidNameSource.Account, (SidNameUse)use[i], false))
                           .Where(n => n.NameUse != SidNameUse.Unknown).ToList().AsReadOnly();
                }
            }
        }

        #endregion

        #region Internal Members
        internal SamDomain(SafeSamHandle handle, SamDomainAccessRights granted_access, string server_name, string domain_name, Sid domain_sid)
            : base(handle, granted_access, SamUtils.SAM_DOMAIN_NT_TYPE_NAME, $"SAM Domain ({domain_name ?? domain_sid.ToString()})", server_name)
        {
            DomainId = domain_sid;
            if (domain_name != null)
            {
                _name = new Lazy<string>(() => domain_name);
            }
            else
            {
                _name = new Lazy<string>(() => string.Empty);
            }
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// The domain name.
        /// </summary>
        public string Name => _name.Value;
        /// <summary>
        /// The domain SID.
        /// </summary>
        public Sid DomainId { get; }
        #endregion

        #region Public Methods
        /// <summary>
        /// Lookup names in a domain.
        /// </summary>
        /// <param name="names">The list of names to lookup.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of looked up SID names.</returns>
        public NtResult<IReadOnlyList<SidName>> LookupNames(IEnumerable<string> names, bool throw_on_error)
        {
            UnicodeStringIn[] lookup_names = names.Select(n => new UnicodeStringIn(n)).ToArray();
            return SecurityNativeMethods.SamLookupNamesInDomain(Handle, lookup_names.Length, 
                lookup_names, out SafeSamMemoryBuffer rids, out SafeSamMemoryBuffer use)
                .CreateResult(throw_on_error, () => MapNames(names.ToArray(), rids, use));
        }

        /// <summary>
        /// Lookup names in a domain.
        /// </summary>
        /// <param name="names">The list of names to lookup.</param>
        /// <returns>The list of looked up SID names.</returns>
        public IReadOnlyList<SidName> LookupNames(IEnumerable<string> names)
        {
            return LookupNames(names, true).Result;
        }

        /// <summary>
        /// Lookup a name in a domain.
        /// </summary>
        /// <param name="name">The name to lookup.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The SID name.</returns>
        public NtResult<SidName> LookupName(string name, bool throw_on_error)
        {
            return LookupNames(new string[] { name }, throw_on_error).Map(l => l.First());
        }

        /// <summary>
        /// Lookup a name in a domain.
        /// </summary>
        /// <param name="name">The name to lookup.</param>
        /// <returns>The SID name.</returns>
        public SidName LookupName(string name)
        {
            return LookupName(name, true).Result;
        }

        /// <summary>
        /// Lookup relative IDs in a domain.
        /// </summary>
        /// <param name="rids">The list of relative IDs to lookup.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of looked up SID names.</returns>
        public NtResult<IReadOnlyList<SidName>> LookupIds(IEnumerable<uint> rids, bool throw_on_error)
        {
            uint[] rids_lookup = rids.ToArray();
            return SecurityNativeMethods.SamLookupIdsInDomain(Handle, rids_lookup.Length,
                rids_lookup, out SafeSamMemoryBuffer names, out SafeSamMemoryBuffer use)
                .CreateResult(throw_on_error, () => MapIds(rids_lookup, names, use));
        }

        /// <summary>
        /// Lookup relative IDs in a domain.
        /// </summary>
        /// <param name="rids">The list of relative IDs to lookup.</param>
        /// <returns>The list of looked up SID names.</returns>
        public IReadOnlyList<SidName> LookupIds(IEnumerable<uint> rids)
        {
            return LookupIds(rids, true).Result;
        }

        /// <summary>
        /// Lookup a rid in a domain.
        /// </summary>
        /// <param name="rid">The relative ID to lookup.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The SID name.</returns>
        public NtResult<SidName> LookupId(uint rid, bool throw_on_error)
        {
            return LookupIds(new uint[] { rid }, throw_on_error).Map(l => l.First());
        }

        /// <summary>
        /// Lookup a rid in a domain.
        /// </summary>
        /// <param name="rid">The relative ID to lookup.</param>
        /// <returns>The SID name.</returns>
        public SidName LookupId(uint rid)
        {
            return LookupId(rid, true).Result;
        }

        /// <summary>
        /// Enumerate users in a domain.
        /// </summary>
        /// <param name="user_account_control">User account control flags.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of users.</returns>
        public NtResult<IReadOnlyList<SamRidEnumeration>> EnumerateUsers(UserAccountControlFlags user_account_control, bool throw_on_error)
        {
            SecurityEnumDelegate<SafeSamHandle, SafeSamMemoryBuffer> enum_func = 
                (SafeSamHandle handle, ref int context, out SafeSamMemoryBuffer buffer, int max_count, out int entries_read) =>
                SecurityNativeMethods.SamEnumerateUsersInDomain(handle, ref context, user_account_control, out buffer, max_count, out entries_read);

            return SamUtils.SamEnumerateObjects(Handle,
                enum_func, (SAM_RID_ENUMERATION s) => new SamRidEnumeration(s), throw_on_error);
        }

        /// <summary>
        /// Enumerate users in a domain.
        /// </summary>
        /// <param name="user_account_control">User account control flags.</param>
        /// <returns>The list of users.</returns>
        public IReadOnlyList<SamRidEnumeration> EnumerateUsers(UserAccountControlFlags user_account_control)
        {
            return EnumerateUsers(user_account_control, true).Result;
        }

        /// <summary>
        /// Enumerate users in a domain.
        /// </summary>
        /// <returns>The list of users.</returns>
        public IReadOnlyList<SamRidEnumeration> EnumerateUsers()
        {
            return EnumerateUsers(UserAccountControlFlags.None);
        }

        /// <summary>
        /// Enumerate groups in a domain.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of groups.</returns>
        public NtResult<IReadOnlyList<SamRidEnumeration>> EnumerateGroups(bool throw_on_error)
        {
            return SamUtils.SamEnumerateObjects(Handle,
                SecurityNativeMethods.SamEnumerateGroupsInDomain, 
                (SAM_RID_ENUMERATION s) => new SamRidEnumeration(s), throw_on_error);
        }

        /// <summary>
        /// Enumerate groups in a domain.
        /// </summary>
        /// <returns>The list of groups.</returns>
        public IReadOnlyList<SamRidEnumeration> EnumerateGroups()
        {
            return EnumerateGroups(true).Result;
        }

        /// <summary>
        /// Enumerate aliases in a domain.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of aliases.</returns>
        public NtResult<IReadOnlyList<SamRidEnumeration>> EnumerateAliases(bool throw_on_error)
        {
            return SamUtils.SamEnumerateObjects(Handle,
                SecurityNativeMethods.SamEnumerateAliasesInDomain,
                (SAM_RID_ENUMERATION s) => new SamRidEnumeration(s), throw_on_error);
        }

        /// <summary>
        /// Enumerate aliases in a domain.
        /// </summary>
        /// <returns>The list of aliases.</returns>
        public IReadOnlyList<SamRidEnumeration> EnumerateAliases()
        {
            return EnumerateAliases(true).Result;
        }

        #endregion
    }
}
