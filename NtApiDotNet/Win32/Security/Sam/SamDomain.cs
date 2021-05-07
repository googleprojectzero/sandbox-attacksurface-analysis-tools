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

        private T CreateObject<T>(SafeSamHandle handle, uint user_id, string name, Func<string, Sid, T> func)
        {
            try
            {
                Sid sid = RidToSid(user_id, false).GetResultOrDefault();
                if (sid == null)
                {
                    sid = DomainId.CreateRelative(user_id);
                }

                if (name == null)
                {
                    name = LookupId(user_id, false).GetResultOrDefault()?.Name ?? sid.ToString();
                }

                return func(name, sid);
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        private NtResult<SamUser> OpenUser(uint user_id, string name, SamUserAccessRights desired_access, bool throw_on_error)
        {

            return SecurityNativeMethods.SamOpenUser(Handle, desired_access, user_id, out SafeSamHandle handle).CreateResult(throw_on_error,
                () => CreateObject(handle, user_id, name, (n, s) => new SamUser(handle, desired_access, ServerName, n, s)));
        }

        private NtResult<SamGroup> OpenGroup(uint group_id, string name, SamGroupAccessRights desired_access, bool throw_on_error)
        {
            return SecurityNativeMethods.SamOpenGroup(Handle, desired_access, group_id, out SafeSamHandle handle).CreateResult(throw_on_error,
                () => CreateObject(handle, group_id, name, (n, s) => new SamGroup(handle, desired_access, ServerName, n, s)));
        }

        private NtResult<SamAlias> OpenAlias(uint alias_id, string name, SamAliasAccessRights desired_access, bool throw_on_error)
        {
            return SecurityNativeMethods.SamOpenAlias(Handle, desired_access, alias_id, out SafeSamHandle handle).CreateResult(throw_on_error,
                () => CreateObject(handle, alias_id, name, (n, s) => new SamAlias(handle, desired_access, ServerName, n, s)));
        }

        private NtResult<SafeSamMemoryBuffer> QueryBuffer<T>(DomainInformationClass info_class, bool throw_on_error) where T : struct
        {
            return SecurityNativeMethods.SamQueryInformationDomain(Handle, info_class, out SafeSamMemoryBuffer buffer).CreateResult(throw_on_error, () =>
            {
                buffer.Initialize<T>(1);
                return buffer;
            });
        }

        private NtResult<SafeSamMemoryBuffer> QueryBuffer(DomainInformationClass info_class, bool throw_on_error)
        {
            return SecurityNativeMethods.SamQueryInformationDomain(Handle, info_class, out SafeSamMemoryBuffer buffer).CreateResult(throw_on_error, () =>
            {
                return buffer;
            });
        }

        private NtResult<T> Query<T>(DomainInformationClass info_class, bool throw_on_error) where T : struct
        {
            using (var buffer = QueryBuffer(info_class, throw_on_error))
            {
                if (!buffer.IsSuccess)
                    return buffer.Cast<T>();
                buffer.Result.Initialize<T>(1);
                return buffer.Result.Read<T>(0).CreateResult();
            }
        }

        private static UserAccountControlFlags AccountTypeToFlags(SamUserAccountType account_type)
        {
            switch (account_type)
            {
                case SamUserAccountType.User:
                    return UserAccountControlFlags.NormalAccount;
                case SamUserAccountType.Workstation:
                    return UserAccountControlFlags.WorkstationTrustAccount;
                case SamUserAccountType.Server:
                    return UserAccountControlFlags.ServerTrustAccount;
                case SamUserAccountType.InterDomain:
                    return UserAccountControlFlags.InterDomainTrustAccount;
                case SamUserAccountType.TempDuplicate:
                    return UserAccountControlFlags.InterDomainTrustAccount;
                default:
                    throw new ArgumentException("Invalid account type.", nameof(account_type));
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
        /// <summary>
        /// Get domain password information
        /// </summary>
        public SamDomainPasswordInformation PasswordInformation => GetPasswordInformation(true).Result;
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

        /// <summary>
        /// Get alias membership for a set of SIDs.
        /// </summary>
        /// <param name="sids">The SIDs to check.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The alias enumeration.</returns>
        public NtResult<IReadOnlyList<SamRidEnumeration>> GetAliasMembership(IEnumerable<Sid> sids, bool throw_on_error)
        {
            using (var list = new DisposableList())
            {
                var alias_list = EnumerateAliases(throw_on_error);
                if (!alias_list.IsSuccess)
                    return alias_list;
                var sid_ptrs = sids.Select(s => list.AddSid(s).DangerousGetHandle()).ToArray();
                return SecurityNativeMethods.SamGetAliasMembership(Handle, sid_ptrs.Length, sid_ptrs,
                    out int count, out SafeSamMemoryBuffer aliases).CreateResult<IReadOnlyList<SamRidEnumeration>>(throw_on_error, () => {
                        using (aliases)
                        {
                            aliases.Initialize<uint>((uint)count);
                            var membership = new HashSet<uint>(aliases.ReadArray<uint>(0, count));
                            return alias_list.Result.Where(m => membership.Contains(m.RelativeId)).ToList().AsReadOnly();
                        }
                    });
            }
        }

        /// <summary>
        /// Get alias membership for a set of SIDs.
        /// </summary>
        /// <param name="sids">The SIDs to check.</param>
        /// <returns>The alias enumeration.</returns>
        public IReadOnlyList<SamRidEnumeration> GetAliasMembership(IEnumerable<Sid> sids)
        {
            return GetAliasMembership(sids, true).Result;
        }

        /// <summary>
        /// Get alias membership for a SID.
        /// </summary>
        /// <param name="sid">The SID to check.</param>
        /// <returns>The alias enumeration.</returns>
        public IReadOnlyList<SamRidEnumeration> GetAliasMembership(Sid sid)
        {
            return GetAliasMembership(new Sid[] { sid });
        }

        /// <summary>
        /// Open a user by relative ID.
        /// </summary>
        /// <param name="user_id">The user ID for the user.</param>
        /// <param name="desired_access">The desired access for the user object.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The SAM user object.</returns>
        public NtResult<SamUser> OpenUser(uint user_id, SamUserAccessRights desired_access, bool throw_on_error)
        {
            return OpenUser(user_id, null, desired_access, throw_on_error);
        }

        /// <summary>
        /// Open a user by relative ID.
        /// </summary>
        /// <param name="user_id">The user ID for the user.</param>
        /// <param name="desired_access">The desired access for the user object.</param>
        /// <returns>The SAM user object.</returns>
        public SamUser OpenUser(uint user_id, SamUserAccessRights desired_access)
        {
            return OpenUser(user_id, desired_access, true).Result;
        }

        /// <summary>
        /// Open a user by SID.
        /// </summary>
        /// <param name="sid">The sid for the user.</param>
        /// <param name="desired_access">The desired access for the user object.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The SAM user object.</returns>
        public NtResult<SamUser> OpenUser(Sid sid, SamUserAccessRights desired_access, bool throw_on_error)
        {
            if (sid.SubAuthorities.Count != DomainId.SubAuthorities.Count + 1 || !sid.StartsWith(DomainId))
            {
                return NtStatus.STATUS_NO_SUCH_DOMAIN.CreateResultFromError<SamUser>(throw_on_error);
            }

            return OpenUser(sid.SubAuthorities.Last(), null, desired_access, throw_on_error);
        }

        /// <summary>
        /// Open a user by SID.
        /// </summary>
        /// <param name="sid">The sid for the user.</param>
        /// <param name="desired_access">The desired access for the user object.</param>
        /// <returns>The SAM user object.</returns>
        public SamUser OpenUser(Sid sid, SamUserAccessRights desired_access)
        {
            return OpenUser(sid, desired_access, true).Result;
        }

        /// <summary>
        /// Open a user by name.
        /// </summary>
        /// <param name="name">The user name for the user.</param>
        /// <param name="desired_access">The desired access for the user object.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The SAM user object.</returns>
        public NtResult<SamUser> OpenUser(string name, SamUserAccessRights desired_access, bool throw_on_error)
        {
            var sid_name = LookupName(name, throw_on_error);
            if (!sid_name.IsSuccess)
            {
                return sid_name.Cast<SamUser>();
            }

            var sid = Sid.Parse(sid_name.Result.Sddl, throw_on_error);
            if (!sid.IsSuccess)
            {
                return sid.Cast<SamUser>();
            }

            return OpenUser(sid.Result, desired_access, throw_on_error);
        }

        /// <summary>
        /// Open a user by name.
        /// </summary>
        /// <param name="name">The user name for the user.</param>
        /// <param name="desired_access">The desired access for the user object.</param>
        /// <returns>The SAM user object.</returns>
        public SamUser OpenUser(string name, SamUserAccessRights desired_access)
        {
            return OpenUser(name, desired_access, true).Result;
        }

        /// <summary>
        /// Open a group by relative ID.
        /// </summary>
        /// <param name="group_id">The ID for the group.</param>
        /// <param name="desired_access">The desired access for the group object.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The SAM group object.</returns>
        public NtResult<SamGroup> OpenGroup(uint group_id, SamGroupAccessRights desired_access, bool throw_on_error)
        {
            return OpenGroup(group_id, null, desired_access, throw_on_error);
        }

        /// <summary>
        /// Open a group by relative ID.
        /// </summary>
        /// <param name="group_id">The ID for the group.</param>
        /// <param name="desired_access">The desired access for the group object.</param>
        /// <returns>The SAM group object.</returns>
        public SamGroup OpenGroup(uint group_id, SamGroupAccessRights desired_access)
        {
            return OpenGroup(group_id, desired_access, true).Result;
        }

        /// <summary>
        /// Open a group by SID.
        /// </summary>
        /// <param name="sid">The sid for the group.</param>
        /// <param name="desired_access">The desired access for the group object.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The SAM group object.</returns>
        public NtResult<SamGroup> OpenGroup(Sid sid, SamGroupAccessRights desired_access, bool throw_on_error)
        {
            if (sid.SubAuthorities.Count != DomainId.SubAuthorities.Count + 1 || !sid.StartsWith(DomainId))
            {
                return NtStatus.STATUS_NO_SUCH_DOMAIN.CreateResultFromError<SamGroup>(throw_on_error);
            }

            return OpenGroup(sid.SubAuthorities.Last(), null, desired_access, throw_on_error);
        }

        /// <summary>
        /// Open a group by SID.
        /// </summary>
        /// <param name="sid">The sid for the group.</param>
        /// <param name="desired_access">The desired access for the group object.</param>
        /// <returns>The SAM group object.</returns>
        public SamGroup OpenGroup(Sid sid, SamGroupAccessRights desired_access)
        {
            return OpenGroup(sid, desired_access, true).Result;
        }

        /// <summary>
        /// Open a group by name.
        /// </summary>
        /// <param name="name">The name for the group.</param>
        /// <param name="desired_access">The desired access for the group object.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The SAM group object.</returns>
        public NtResult<SamGroup> OpenGroup(string name, SamGroupAccessRights desired_access, bool throw_on_error)
        {
            var sid_name = LookupName(name, throw_on_error);
            if (!sid_name.IsSuccess)
            {
                return sid_name.Cast<SamGroup>();
            }

            var sid = Sid.Parse(sid_name.Result.Sddl, throw_on_error);
            if (!sid.IsSuccess)
            {
                return sid.Cast<SamGroup>();
            }

            return OpenGroup(sid.Result, desired_access, throw_on_error);
        }

        /// <summary>
        /// Open a group by name.
        /// </summary>
        /// <param name="name">The name for the group.</param>
        /// <param name="desired_access">The desired access for the group object.</param>
        /// <returns>The SAM group object.</returns>
        public SamGroup OpenGroup(string name, SamGroupAccessRights desired_access)
        {
            return OpenGroup(name, desired_access, true).Result;
        }

        /// <summary>
        /// Create a new group object.
        /// </summary>
        /// <param name="name">The name of the group.</param>
        /// <param name="desired_access">The desired access for the group object.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The SAM group object.</returns>
        public NtResult<SamGroup> CreateGroup(string name, SamGroupAccessRights desired_access, bool throw_on_error)
        {
            return SecurityNativeMethods.SamCreateGroupInDomain(Handle, new UnicodeString(name), desired_access,
                out SafeSamHandle group_handle, out uint rid).CreateResult(throw_on_error,
                () => new SamGroup(group_handle, desired_access, ServerName, name, DomainId.CreateRelative(rid)));
        }

        /// <summary>
        /// Create a new group object.
        /// </summary>
        /// <param name="name">The name of the group.</param>
        /// <param name="desired_access">The desired access for the group object.</param>
        /// <returns>The SAM group object.</returns>
        public SamGroup CreateGroup(string name, SamGroupAccessRights desired_access)
        {
            return CreateGroup(name, desired_access, true).Result;
        }

        /// <summary>
        /// Create a new group object.
        /// </summary>
        /// <param name="name">The name of the group.</param>
        /// <returns>The SAM group object.</returns>
        public SamGroup CreateGroup(string name)
        {
            return CreateGroup(name, SamGroupAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Create a new user in the SAM.
        /// </summary>
        /// <param name="name">The name of the user.</param>
        /// <param name="account_type">The type of account.</param>
        /// <param name="desired_access">Desired access for new user.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The SAM user object.</returns>
        public NtResult<SamUser> CreateUser(string name, SamUserAccountType account_type,
            SamUserAccessRights desired_access, bool throw_on_error)
        {
            return SecurityNativeMethods.SamCreateUser2InDomain(Handle, new UnicodeString(name), AccountTypeToFlags(account_type),
                desired_access, out SafeSamHandle user_handle,
                out SamUserAccessRights granted_access, out uint rid).CreateResult(throw_on_error, 
                () => new SamUser(user_handle, granted_access, ServerName, name, DomainId.CreateRelative(rid)));
        }

        /// <summary>
        /// Create a new user in the SAM.
        /// </summary>
        /// <param name="name">The name of the user.</param>
        /// <param name="account_type">The type of account.</param>
        /// <param name="desired_access">Desired access for new user.</param>
        /// <returns>The SAM user object.</returns>
        public SamUser CreateUser(string name, SamUserAccountType account_type,
            SamUserAccessRights desired_access)
        {
            return CreateUser(name, account_type, desired_access, true).Result;
        }

        /// <summary>
        /// Open an alias by relative ID.
        /// </summary>
        /// <param name="alias_id">The ID for the alias.</param>
        /// <param name="desired_access">The desired access for the alias object.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The SAM alias object.</returns>
        public NtResult<SamAlias> OpenAlias(uint alias_id, SamAliasAccessRights desired_access, bool throw_on_error)
        {
            return OpenAlias(alias_id, null, desired_access, throw_on_error);
        }

        /// <summary>
        /// Open an alias by relative ID.
        /// </summary>
        /// <param name="alias_id">The ID for the alias.</param>
        /// <param name="desired_access">The desired access for the alias object.</param>
        /// <returns>The SAM alias object.</returns>
        public SamAlias OpenAlias(uint alias_id, SamAliasAccessRights desired_access)
        {
            return OpenAlias(alias_id, desired_access, true).Result;
        }

        /// <summary>
        /// Open an alias by SID.
        /// </summary>
        /// <param name="sid">The sid for the alias.</param>
        /// <param name="desired_access">The desired access for the alias object.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The SAM alias object.</returns>
        public NtResult<SamAlias> OpenAlias(Sid sid, SamAliasAccessRights desired_access, bool throw_on_error)
        {
            if (sid.SubAuthorities.Count != DomainId.SubAuthorities.Count + 1 || !sid.StartsWith(DomainId))
            {
                return NtStatus.STATUS_NO_SUCH_DOMAIN.CreateResultFromError<SamAlias>(throw_on_error);
            }

            return OpenAlias(sid.SubAuthorities.Last(), null, desired_access, throw_on_error);
        }

        /// <summary>
        /// Open an alias by SID.
        /// </summary>
        /// <param name="sid">The sid for the alias.</param>
        /// <param name="desired_access">The desired access for the alias object.</param>
        /// <returns>The SAM alias object.</returns>
        public SamAlias OpenAlias(Sid sid, SamAliasAccessRights desired_access)
        {
            return OpenAlias(sid, desired_access, true).Result;
        }

        /// <summary>
        /// Open an alias by name.
        /// </summary>
        /// <param name="name">The name for the alias.</param>
        /// <param name="desired_access">The desired access for the alias object.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The SAM alias object.</returns>
        public NtResult<SamAlias> OpenAlias(string name, SamAliasAccessRights desired_access, bool throw_on_error)
        {
            var sid_name = LookupName(name, throw_on_error);
            if (!sid_name.IsSuccess)
            {
                return sid_name.Cast<SamAlias>();
            }

            var sid = Sid.Parse(sid_name.Result.Sddl, throw_on_error);
            if (!sid.IsSuccess)
            {
                return sid.Cast<SamAlias>();
            }

            return OpenAlias(sid.Result, desired_access, throw_on_error);
        }

        /// <summary>
        /// Open an alias by name.
        /// </summary>
        /// <param name="name">The name for the alias.</param>
        /// <param name="desired_access">The desired access for the alias object.</param>
        /// <returns>The SAM alias object.</returns>
        public SamAlias OpenAlias(string name, SamAliasAccessRights desired_access)
        {
            return OpenAlias(name, desired_access, true).Result;
        }

        /// <summary>
        /// Enumerate and open accessible user objects.
        /// </summary>
        /// <param name="user_account_control">User account control flags.</param>
        /// <param name="desired_access">The desired access for the opened users.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of accessible users.</returns>
        public NtResult<IReadOnlyList<SamUser>> OpenAccessibleUsers(UserAccountControlFlags user_account_control, SamUserAccessRights desired_access, bool throw_on_error)
        {
            return EnumerateUsers(user_account_control, throw_on_error).Map<IReadOnlyList<SamUser>>(e => e.Select(
                s => OpenUser(s.RelativeId, s.Name, desired_access, false).GetResultOrDefault()).Where(a => a != null).ToList().AsReadOnly());
        }

        /// <summary>
        /// Enumerate and open accessible user objects.
        /// </summary>
        /// <param name="user_account_control">User account control flags.</param>
        /// <param name="desired_access">The desired access for the opened users.</param>
        /// <returns>The list of accessible users.</returns>
        public IReadOnlyList<SamUser> OpenAccessibleUsers(UserAccountControlFlags user_account_control, SamUserAccessRights desired_access)
        {
            return OpenAccessibleUsers(user_account_control, desired_access, true).Result;
        }

        /// <summary>
        /// Enumerate and open accessible user objects with maximum access.
        /// </summary>
        /// <returns>The list of accessible users.</returns>
        public IReadOnlyList<SamUser> OpenAccessibleUsers()
        {
            return OpenAccessibleUsers(UserAccountControlFlags.None, SamUserAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Enumerate and open accessible group objects.
        /// </summary>
        /// <param name="desired_access">The desired access for the opened groups.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of accessible groups.</returns>
        public NtResult<IReadOnlyList<SamGroup>> OpenAccessibleGroups(SamGroupAccessRights desired_access, bool throw_on_error)
        {
            return EnumerateGroups(throw_on_error).Map<IReadOnlyList<SamGroup>>(e => e.Select(
                s => OpenGroup(s.RelativeId, s.Name, desired_access, false).GetResultOrDefault()).Where(a => a != null).ToList().AsReadOnly());
        }

        /// <summary>
        /// Enumerate and open accessible group objects.
        /// </summary>
        /// <param name="desired_access">The desired access for the opened groups.</param>
        /// <returns>The list of accessible groups.</returns>
        public IReadOnlyList<SamGroup> OpenAccessibleGroups(SamGroupAccessRights desired_access)
        {
            return OpenAccessibleGroups(desired_access, true).Result;
        }

        /// <summary>
        /// Enumerate and open accessible group objects with maximum access.
        /// </summary>
        /// <returns>The list of accessible groups.</returns>
        public IReadOnlyList<SamGroup> OpenAccessibleGroups()
        {
            return OpenAccessibleGroups(SamGroupAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Enumerate and open accessible alias objects.
        /// </summary>
        /// <param name="desired_access">The desired access for the opened aliases.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of accessible aliases.</returns>
        public NtResult<IReadOnlyList<SamAlias>> OpenAccessibleAliases(SamAliasAccessRights desired_access, bool throw_on_error)
        {
            return EnumerateAliases(throw_on_error).Map<IReadOnlyList<SamAlias>>(e => e.Select(
                s => OpenAlias(s.RelativeId, s.Name, desired_access, false).GetResultOrDefault()).Where(a => a != null).ToList().AsReadOnly());
        }

        /// <summary>
        /// Enumerate and open accessible alias objects.
        /// </summary>
        /// <param name="desired_access">The desired access for the opened aliases.</param>
        /// <returns>The list of accessible aliases.</returns>
        public IReadOnlyList<SamAlias> OpenAccessibleAliases(SamAliasAccessRights desired_access)
        {
            return OpenAccessibleAliases(desired_access, true).Result;
        }

        /// <summary>
        /// Enumerate and open accessible alias objects with maximum access.
        /// </summary>
        /// <returns>The list of accessible aliases.</returns>
        public IReadOnlyList<SamAlias> OpenAccessibleAliases()
        {
            return OpenAccessibleAliases(SamAliasAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Convert a RID to a SID for the current object.
        /// </summary>
        /// <param name="relative_id">The relative ID.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The converted SID.</returns>
        public NtResult<Sid> RidToSid(uint relative_id, bool throw_on_error)
        {
            return SecurityNativeMethods.SamRidToSid(Handle, relative_id, out SafeSamMemoryBuffer buffer).CreateResult(throw_on_error, () =>
            {
                using (buffer)
                {
                    return new Sid(buffer);
                }
            }
            );
        }

        /// <summary>
        /// Convert a RID to a SID for the current object.
        /// </summary>
        /// <param name="relative_id">The relative ID.</param>
        /// <returns>The converted SID.</returns>
        public Sid RidToSid(uint relative_id)
        {
            return RidToSid(relative_id, true).Result;
        }

        /// <summary>
        /// Get password information.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns></returns>
        public NtResult<SamDomainPasswordInformation> GetPasswordInformation(bool throw_on_error)
        {
            var info = Query<DOMAIN_PASSWORD_INFORMATION>(DomainInformationClass.DomainPasswordInformation, throw_on_error);
            if (!info.IsSuccess)
                return info.Cast<SamDomainPasswordInformation>();
            return new SamDomainPasswordInformation(info.Result).CreateResult();
        }
        #endregion
    }
}