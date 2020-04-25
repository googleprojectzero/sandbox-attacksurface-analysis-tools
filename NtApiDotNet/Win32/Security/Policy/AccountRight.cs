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
    public class AccountRight
    {
        private readonly List<Sid> _cached_sids;
        private readonly Lazy<List<Sid>> _sids;
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
        public IEnumerable<Sid> Sids => (_cached_sids ?? _sids.Value).AsReadOnly();

        /// <summary>
        /// ToString method.
        /// </summary>
        /// <returns>The name of the account right.</returns>
        public override string ToString() => Name;

        private static List<Sid> ParseSids(SafeLsaMemoryBuffer buffer, int count)
        {
            using (buffer)
            {
                buffer.Initialize<LSA_ENUMERATION_INFORMATION>((uint)count);
                LSA_ENUMERATION_INFORMATION[] ss = new LSA_ENUMERATION_INFORMATION[count];
                buffer.ReadArray(0, ss, 0, count);
                return ss.Select(s => new Sid(s.Sid)).ToList();
            }
        }

        private static NtResult<List<Sid>> GetSids(SafeLsaHandle policy, string name, bool throw_on_error)
        {
            if (name is null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            NtStatus status = SecurityNativeMethods.LsaEnumerateAccountsWithUserRight(policy, new UnicodeString(name),
                out SafeLsaMemoryBuffer buffer, out int count);
            if (status == NtStatus.STATUS_NO_MORE_ENTRIES)
                return new List<Sid>().CreateResult();
            return status.CreateResult(throw_on_error, () => ParseSids(buffer, count));
        }

        internal static NtResult<List<Sid>> GetSids(string system_name, string name, bool throw_on_error)
        {
            using (var policy = SafeLsaHandle.OpenPolicy(system_name, LsaPolicyAccessRights.GenericExecute, throw_on_error))
            {
                if (!policy.IsSuccess)
                    return policy.Cast<List<Sid>>();
                return GetSids(policy.Result, name, throw_on_error);
            }
        }

        private static IEnumerable<AccountRight> ParseRights(SafeLsaHandle policy, string system_name, SafeLsaMemoryBuffer buffer, int count)
        {
            using (buffer)
            {
                buffer.Initialize<UnicodeStringOut>((uint)count);
                UnicodeStringOut[] ss = new UnicodeStringOut[count];
                buffer.ReadArray(0, ss, 0, count);
                return ss.Select(s => new AccountRight(system_name, s.ToString(), 
                    GetSids(policy, s.ToString(), false).GetResultOrDefault())).ToList();
            }
        }

        internal static NtResult<IEnumerable<AccountRight>> GetAccountRights(string system_name, Sid sid, bool throw_on_error)
        {
            if (sid is null)
            {
                throw new ArgumentNullException(nameof(sid));
            }

            using (var policy = SafeLsaHandle.OpenPolicy(system_name, LsaPolicyAccessRights.GenericExecute, throw_on_error))
            {
                if (!policy.IsSuccess)
                    return policy.Cast<IEnumerable<AccountRight>>();
                using (var sid_buffer = sid.ToSafeBuffer())
                {
                    return SecurityNativeMethods.LsaEnumerateAccountRights(policy.Result, sid_buffer,
                        out SafeLsaMemoryBuffer buffer, out int count)
                        .CreateResult(throw_on_error, () => ParseRights(policy.Result, system_name, buffer, count));
                }
            }
        }

        internal AccountRight(string system_name, string name, List<Sid> cached_sids)
        {
            Name = name;
            _display_name = new Lazy<string>(() => Win32Security.LookupPrivilegeDisplayName(system_name, name));
            _cached_sids = cached_sids;
            _sids = new Lazy<List<Sid>>(() => GetSids(system_name, name, false).GetResultOrDefault(new List<Sid>()));
            _system_name = system_name;
        }
    }
}
