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
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Policy
{
    /// <summary>
    /// Class to represent an Account Right assigned to a user.
    /// </summary>
    public sealed class AccountRight
    {
        private readonly IEnumerable<Sid> _cached_sids;
        private readonly Lazy<IEnumerable<Sid>> _sids;
        private readonly Lazy<string> _display_name;
        private readonly string _system_name;

        /// <summary>
        /// The name of the account right.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// The display name, if known.
        /// </summary>
        public string DisplayName => _display_name.Value;

        /// <summary>
        /// Get list of SIDS assigned to this access right.
        /// </summary>
        public IEnumerable<Sid> Sids => _cached_sids ?? _sids.Value;

        /// <summary>
        /// ToString method.
        /// </summary>
        /// <returns>The name of the account right.</returns>
        public override string ToString() => Name;

        internal static NtResult<IReadOnlyList<Sid>> GetSids(string system_name, string name, bool throw_on_error)
        {
            using (var policy = LsaPolicy.Open(system_name, LsaPolicyAccessRights.GenericExecute, throw_on_error))
            {
                if (!policy.IsSuccess)
                    return policy.Cast<IReadOnlyList<Sid>>();
                return policy.Result.EnumerateAccountsWithUserRight(name, throw_on_error);
            }
        }

        internal static NtResult<IEnumerable<AccountRight>> GetAccountRights(string system_name, Sid sid, bool throw_on_error)
        {
            if (sid is null)
            {
                throw new ArgumentNullException(nameof(sid));
            }

            using (var policy = LsaPolicy.Open(system_name, LsaPolicyAccessRights.GenericExecute, throw_on_error))
            {
                if (!policy.IsSuccess)
                    return policy.Cast<IEnumerable<AccountRight>>();

                var account_rights = policy.Result.EnumerateAccountRights(sid, throw_on_error);
                if (!account_rights.IsSuccess)
                    return account_rights.Cast<IEnumerable<AccountRight>>();

                return account_rights.Result.Select(s => new AccountRight(system_name, s,
                    policy.Result.EnumerateAccountsWithUserRight(s, false).GetResultOrDefault()))
                    .ToList().AsReadOnly().CreateResult<IEnumerable<AccountRight>>();
            }
        }

        internal static NtStatus AddAccountRights(string system_name, Sid sid, IEnumerable<string> account_rights, bool throw_on_error)
        {
            if (sid is null)
            {
                throw new ArgumentNullException(nameof(sid));
            }

            if (account_rights is null)
            {
                throw new ArgumentNullException(nameof(account_rights));
            }

            using (var policy = LsaPolicy.Open(system_name, 
                LsaPolicyAccessRights.LookupNames | LsaPolicyAccessRights.CreateAccount, throw_on_error))
            {
                if (!policy.IsSuccess)
                    return policy.Status;
                return policy.Result.AddAccountRights(sid, account_rights, throw_on_error);
            }
        }

        internal static NtStatus RemoveAccountRights(string system_name, Sid sid, bool remove_all, IEnumerable<string> account_rights, bool throw_on_error)
        {
            if (sid is null)
            {
                throw new ArgumentNullException(nameof(sid));
            }

            if (account_rights is null)
            {
                throw new ArgumentNullException(nameof(account_rights));
            }

            using (var policy = LsaPolicy.Open(system_name, LsaPolicyAccessRights.LookupNames, throw_on_error))
            {
                if (!policy.IsSuccess)
                    return policy.Status;
                return policy.Result.RemoveAccountRights(sid, remove_all, account_rights, throw_on_error);
            }
        }

        internal AccountRight(string system_name, string name, IEnumerable<Sid> cached_sids)
        {
            Name = name;
            _display_name = new Lazy<string>(() => Win32Security.LookupPrivilegeDisplayName(system_name, name));
            _cached_sids = cached_sids;
            _sids = new Lazy<IEnumerable<Sid>>(() => GetSids(system_name, name, false).GetResultOrDefault(new Sid[0]));
            _system_name = system_name;
        }
    }
}
