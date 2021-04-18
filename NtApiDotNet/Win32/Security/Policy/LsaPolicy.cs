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

namespace NtApiDotNet.Win32.Security.Policy
{
    /// <summary>
    /// Class to represent the LSA policy.
    /// </summary>
    public sealed class LsaPolicy : LsaObject
    {
        #region Private Members
        private delegate NtStatus LookupSidsDelegate(IntPtr[] sid_ptrs, out SafeLsaMemoryBuffer domains, out SafeLsaMemoryBuffer names);

        private LsaPolicy(SafeLsaHandle handle, LsaPolicyAccessRights granted_access, string system_name) 
            : base(handle, granted_access, LsaPolicyUtils.LSA_POLICY_NT_TYPE_NAME, 
                  string.IsNullOrEmpty(system_name) ? "LSA Policy" : $@"LSA Policy (\\{system_name}", system_name)
        {
        }

        private static IReadOnlyList<SidName> GetSidNames(Sid[] sids, SafeLsaMemoryBuffer domains, SafeLsaMemoryBuffer names)
        {
            List<SidName> ret = new List<SidName>();
            domains.Initialize<LSA_REFERENCED_DOMAIN_LIST>(1);
            names.Initialize<LSA_TRANSLATED_NAME>((uint)sids.Length);

            var domain_list = domains.Read<LSA_REFERENCED_DOMAIN_LIST>(0);
            var domains_entries = NtProcess.Current.ReadMemoryArray<LSA_TRUST_INFORMATION>(domain_list.Domains.ToInt64(), domain_list.Entries);
            var name_list = names.ReadArray<LSA_TRANSLATED_NAME>(0, sids.Length);

            for (int i = 0; i < sids.Length; ++i)
            {
                var name = name_list[i];

                ret.Add(new SidName(sids[i], name.GetDomain(domains_entries),
                    name.GetName(), SidNameSource.Account, name.Use, false));
            }
            return ret.AsReadOnly();
        }

        private static IReadOnlyList<SidName> GetSidNameSids(string[] names, SafeLsaMemoryBuffer domains, SafeLsaMemoryBuffer sids)
        {
            using (SafeBufferGeneric a = domains, b = sids)
            {
                List<SidName> ret = new List<SidName>();
                domains.Initialize<LSA_REFERENCED_DOMAIN_LIST>(1);
                sids.Initialize<LSA_TRANSLATED_SID2>((uint)names.Length);

                var domain_list = domains.Read<LSA_REFERENCED_DOMAIN_LIST>(0);
                var domains_entries = NtProcess.Current.ReadMemoryArray<LSA_TRUST_INFORMATION>(domain_list.Domains.ToInt64(), domain_list.Entries);
                var sid_list = sids.ReadArray<LSA_TRANSLATED_SID2>(0, names.Length);
                for (int i = 0; i < names.Length; ++i)
                {
                    ret.Add(new SidName(sid_list[i].GetSid(), sid_list[i].GetDomain(domains_entries),
                        names[i], SidNameSource.Account, sid_list[i].Use, false));
                }
                return ret.AsReadOnly();
            }
        }

        private static NtResult<IReadOnlyList<SidName>> LookupSids(IEnumerable<Sid> sids, LookupSidsDelegate func, bool throw_on_error)
        {
            using (var list = new DisposableList())
            {
                var sid_ptrs = sids.Select(s => list.AddSid(s).DangerousGetHandle()).ToArray();
                var status = func(sid_ptrs, out SafeLsaMemoryBuffer domains, out SafeLsaMemoryBuffer names);
                if (!status.IsSuccess())
                {
                    if (status == NtStatus.STATUS_NONE_MAPPED)
                    {
                        list.Add(domains);
                        list.Add(names);
                    }
                    return status.CreateResultFromError<IReadOnlyList<SidName>>(throw_on_error);
                }

                list.Add(domains);
                list.Add(names);
                return GetSidNames(sids.ToArray(), domains, names).CreateResult();
            }
        }

        private static IReadOnlyList<Sid> ParseSids(SafeLsaMemoryBuffer buffer, int count)
        {
            using (buffer)
            {
                buffer.Initialize<LSA_ENUMERATION_INFORMATION>((uint)count);
                LSA_ENUMERATION_INFORMATION[] ss = new LSA_ENUMERATION_INFORMATION[count];
                buffer.ReadArray(0, ss, 0, count);
                return ss.Select(s => new Sid(s.Sid)).ToList().AsReadOnly();
            }
        }

        private static IReadOnlyList<string> ParseRights(SafeLsaMemoryBuffer buffer, int count)
        {
            using (buffer)
            {
                buffer.Initialize<UnicodeStringOut>((uint)count);
                return buffer.ReadArray<UnicodeStringOut>(0, count).Select(n => n.ToString()).ToList().AsReadOnly();
            }
        }

        private LsaTrustedDomainInformation QueryDomainInfo(SafeLsaMemoryBuffer buffer)
        {
            using (buffer)
            {
                buffer.Initialize<TRUSTED_DOMAIN_INFORMATION_EX>(1);
                return new LsaTrustedDomainInformation(buffer.Read<TRUSTED_DOMAIN_INFORMATION_EX>(0));
            }
        }

        private LsaTrustedDomainInformation QueryDomainInfo(string name)
        {
            return SecurityNativeMethods.LsaQueryTrustedDomainInfoByName(Handle, new UnicodeString(name),
                TRUSTED_INFORMATION_CLASS.TrustedDomainInformationEx, out SafeLsaMemoryBuffer buffer)
                .CreateResult(false, () => QueryDomainInfo(buffer)).GetResultOrDefault();
        }

        private LsaTrustedDomainInformation QueryDomainInfo(SafeSidBufferHandle sid_buffer)
        {
            return SecurityNativeMethods.LsaQueryTrustedDomainInfo(Handle, sid_buffer,
                TRUSTED_INFORMATION_CLASS.TrustedDomainInformationEx, out SafeLsaMemoryBuffer buffer)
                .CreateResult(false, () => QueryDomainInfo(buffer)).GetResultOrDefault();
        }

        private NtResult<LsaTrustedDomain> OpenTrustedDomain(string name, LsaTrustedDomainInformation? domain_info, LsaTrustedDomainAccessRights desired_access, bool throw_on_error)
        {
            return SecurityNativeMethods.LsaOpenTrustedDomainByName(Handle, new UnicodeString(name),
                desired_access, out SafeLsaHandle handle).CreateResult(throw_on_error,
                () => new LsaTrustedDomain(handle, desired_access, name, null, domain_info ?? QueryDomainInfo(name), SystemName));
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Lookup names for SIDs.
        /// </summary>
        /// <param name="sids">The list of SIDs to lookup.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of looked up SID names.</returns>
        public NtResult<IReadOnlyList<SidName>> LookupSids(IEnumerable<Sid> sids, bool throw_on_error)
        {
            return LookupSids(sids, (IntPtr[] s, out SafeLsaMemoryBuffer d, out SafeLsaMemoryBuffer n)
                => SecurityNativeMethods.LsaLookupSids(Handle, s.Length, s, out d, out n), throw_on_error);
        }

        /// <summary>
        /// Lookup names for SIDs.
        /// </summary>
        /// <param name="sids">The list of SIDs to lookup.</param>
        /// <returns>The list of looked up SID names.</returns>
        public IReadOnlyList<SidName> LookupSids(IEnumerable<Sid> sids)
        {
            return LookupSids(sids, true).Result;
        }

        /// <summary>
        /// Lookup name for a SID.
        /// </summary>
        /// <param name="sid">The SID to lookup.</param>
        /// <returns></returns>
        public SidName LookupSid(Sid sid)
        {
            return LookupSids(new [] { sid }).First();
        }

        /// <summary>
        /// Lookup names for SIDs.
        /// </summary>
        /// <param name="sids">The list of SIDs to lookup.</param>
        /// <param name="options">Lookup options flags.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of looked up SID names.</returns>
        [SupportedVersion(SupportedVersion.Windows8)]
        public NtResult<IReadOnlyList<SidName>> LookupSids2(IEnumerable<Sid> sids, LsaLookupSidOptionFlags options, bool throw_on_error)
        {
            if (NtObjectUtils.IsWindows7OrLess)
                throw new NotSupportedException($"{nameof(LookupSids2)} isn't supported until Windows 8");

            return LookupSids(sids, (IntPtr[] s, out SafeLsaMemoryBuffer d, out SafeLsaMemoryBuffer n) 
                => SecurityNativeMethods.LsaLookupSids2(Handle, options, s.Length, s, out d, out n), throw_on_error);
        }

        /// <summary>
        /// Lookup names for SIDs.
        /// </summary>
        /// <param name="sids">The list of SIDs to lookup.</param>
        /// <param name="options">Lookup options flags.</param>
        /// <returns>The list of looked up SID names.</returns>
        [SupportedVersion(SupportedVersion.Windows8)]
        public IReadOnlyList<SidName> LookupSids2(IEnumerable<Sid> sids, LsaLookupSidOptionFlags options)
        {
            return LookupSids2(sids, options, true).Result;
        }

        /// <summary>
        /// Lookup names from the LSA policy.
        /// </summary>
        /// <param name="names">The names to lookup.</param>
        /// <param name="flags">Flags for the lookup.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of SID names.</returns>
        public NtResult<IReadOnlyList<SidName>> LookupNames(IEnumerable<string> names, LsaLookupNameOptionFlags flags, bool throw_on_error)
        {
            UnicodeStringIn[] name_arr = names.Select(n => new UnicodeStringIn(n)).ToArray();
            return SecurityNativeMethods.LsaLookupNames2(Handle, flags, name_arr.Length, name_arr,
                out SafeLsaMemoryBuffer domains, out SafeLsaMemoryBuffer sids).CreateResult(throw_on_error,
                () => GetSidNameSids(names.ToArray(), domains, sids));
        }

        /// <summary>
        /// Lookup names from the LSA policy.
        /// </summary>
        /// <param name="names">The names to lookup.</param>
        /// <param name="flags">Flags for the lookup.</param>
        /// <returns>The list of SID names.</returns>
        public IReadOnlyList<SidName> LookupNames(IEnumerable<string> names, LsaLookupNameOptionFlags flags)
        {
            return LookupNames(names, flags, true).Result;
        }

        /// <summary>
        /// Lookup names from the LSA policy.
        /// </summary>
        /// <param name="names">The names to lookup.</param>
        /// <returns>The list of SID names.</returns>
        public IReadOnlyList<SidName> LookupNames(IEnumerable<string> names)
        {
            return LookupNames(names, 0);
        }

        /// <summary>
        /// Lookup names from the LSA policy.
        /// </summary>
        /// <param name="name">The name to lookup.</param>
        /// <returns>The looked up SID name.</returns>
        public SidName LookupName(string name)
        {
            return LookupNames(new[] { name }).First();
        }

        /// <summary>
        /// Enumerate accounts with a user right.
        /// </summary>
        /// <param name="user_right">The name of the user right.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of SIDs with the user right.</returns>
        public NtResult<IReadOnlyList<Sid>> EnumerateAccountsWithUserRight(string user_right, bool throw_on_error)
        {
            if (user_right is null)
            {
                throw new ArgumentNullException(nameof(user_right));
            }

            NtStatus status = SecurityNativeMethods.LsaEnumerateAccountsWithUserRight(Handle, 
                new UnicodeString(user_right), out SafeLsaMemoryBuffer buffer, out int count);
            if (status == NtStatus.STATUS_NO_MORE_ENTRIES)
                return new List<Sid>().AsReadOnly().CreateResult<IReadOnlyList<Sid>>();
            return status.CreateResult(throw_on_error, () => ParseSids(buffer, count));
        }

        /// <summary>
        /// Enumerate accounts with a user right.
        /// </summary>
        /// <param name="user_right">The name of the user right.</param>
        /// <returns>The list of SIDs with the user right.</returns>
        public IReadOnlyList<Sid> EnumerateAccountsWithUserRight(string user_right)
        {
            return EnumerateAccountsWithUserRight(user_right, true).Result;
        }

        /// <summary>
        /// Enumerate account rights for a SID.
        /// </summary>
        /// <param name="sid">The SID to enumerate for.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of assigned account rights.</returns>
        public NtResult<IReadOnlyList<string>> EnumerateAccountRights(Sid sid, bool throw_on_error)
        {
            if (sid is null)
            {
                throw new ArgumentNullException(nameof(sid));
            }

            using (var sid_buffer = sid.ToSafeBuffer())
            {
                return SecurityNativeMethods.LsaEnumerateAccountRights(Handle, sid_buffer,
                    out SafeLsaMemoryBuffer buffer, out int count)
                    .CreateResult(throw_on_error, () => ParseRights(buffer, count));
            }
        }

        /// <summary>
        /// Enumerate account rights for a SID.
        /// </summary>
        /// <param name="sid">The SID to enumerate for.</param>
        /// <returns>The list of assigned account rights.</returns>
        public IReadOnlyList<string> EnumerateAccountRights(Sid sid)
        {
            return EnumerateAccountRights(sid, true).Result;
        }

        /// <summary>
        /// Add account rights to an account.
        /// </summary>
        /// <param name="sid">The SID of the account.</param>
        /// <param name="account_rights">The list of account rights to add.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus AddAccountRights(Sid sid, IEnumerable<string> account_rights, bool throw_on_error)
        {
            if (sid is null)
            {
                throw new ArgumentNullException(nameof(sid));
            }

            if (account_rights is null)
            {
                throw new ArgumentNullException(nameof(account_rights));
            }

            var rights = account_rights.Select(s => new UnicodeStringIn(s)).ToArray();
            if (!account_rights.Any())
                return NtStatus.STATUS_SUCCESS;

            using (var sid_buffer = sid.ToSafeBuffer())
            {
                return SecurityNativeMethods.LsaAddAccountRights(Handle, sid_buffer,
                    rights, rights.Length).ToNtException(throw_on_error);
            }
        }

        /// <summary>
        /// Add account rights to an account.
        /// </summary>
        /// <param name="sid">The SID of the account.</param>
        /// <param name="account_rights">The list of account rights to add.</param>
        public void AddAccountRights(Sid sid, IEnumerable<string> account_rights)
        {
            AddAccountRights(sid, account_rights, true);
        }

        /// <summary>
        /// Remove account rights from an account.
        /// </summary>
        /// <param name="sid">The SID of the account.</param>
        /// <param name="remove_all">True to remove all rights.</param>
        /// <param name="account_rights">The account rights to add.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus RemoveAccountRights(Sid sid, bool remove_all, IEnumerable<string> account_rights, bool throw_on_error)
        {
            if (sid is null)
            {
                throw new ArgumentNullException(nameof(sid));
            }

            if (account_rights is null)
            {
                throw new ArgumentNullException(nameof(account_rights));
            }

            var rights = account_rights.Select(s => new UnicodeStringIn(s)).ToArray();

            if (!account_rights.Any() && !remove_all)
                return NtStatus.STATUS_SUCCESS;

            using (var sid_buffer = sid.ToSafeBuffer())
            {
                return SecurityNativeMethods.LsaRemoveAccountRights(Handle,
                    sid_buffer, remove_all, rights, rights.Length).ToNtException(throw_on_error);
            }
        }

        /// <summary>
        /// Remove account rights from an account.
        /// </summary>
        /// <param name="sid">The SID of the account.</param>
        /// <param name="remove_all">True to remove all rights.</param>
        /// <param name="account_rights">The account rights to add.</param>
        public void RemoveAccountRights(Sid sid, bool remove_all, IEnumerable<string> account_rights)
        {
            RemoveAccountRights(sid, remove_all, account_rights, true);
        }

        /// <summary>
        /// Retrieve LSA privilege data.
        /// </summary>
        /// <param name="keyname">The name of the key.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The private data as bytes.</returns>
        public NtResult<byte[]> RetrievePrivateData(string keyname, bool throw_on_error)
        {
            if (keyname is null)
            {
                throw new ArgumentNullException(nameof(keyname));
            }

            NtStatus status = SecurityNativeMethods.LsaRetrievePrivateData(Handle,
                new UnicodeString(keyname), out SafeLsaMemoryBuffer data);
            if (!status.IsSuccess())
                return status.CreateResultFromError<byte[]>(throw_on_error);
            using (data)
            {
                return data.GetUnicodeString().ToArray().CreateResult();
            }
        }

        /// <summary>
        /// Retrieve LSA privilege data.
        /// </summary>
        /// <param name="keyname">The name of the key.</param>
        /// <returns>The private data as bytes.</returns>
        public byte[] RetrievePrivateData(string keyname)
        {
            return RetrievePrivateData(keyname, true).Result;
        }

        /// <summary>
        /// Store LSA private data.
        /// </summary>
        /// <param name="keyname">The name of the key.</param>
        /// <param name="data">The data to store. If you pass null then the value will be deleted.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus StorePrivateData(string keyname, byte[] data, bool throw_on_error)
        {
            if (keyname is null)
            {
                throw new ArgumentNullException(nameof(keyname));
            }

            using (var data_buffer = data == null ? UnicodeStringBytesSafeBuffer.Null : new UnicodeStringBytesSafeBuffer(data))
            {
                return SecurityNativeMethods.LsaStorePrivateData(Handle, new UnicodeString(keyname), data_buffer).ToNtException(throw_on_error);
            }
        }

        /// <summary>
        /// Store LSA private data.
        /// </summary>
        /// <param name="keyname">The name of the key.</param>
        /// <param name="data">The data to store. If you pass null then the value will be deleted.</param>
        public void StorePrivateData(string keyname, byte[] data)
        {
            StorePrivateData(keyname, data, true);
        }

        /// <summary>
        /// Open an LSA secret object.
        /// </summary>
        /// <param name="name">The name of the secret.</param>
        /// <param name="desired_access">The desired access for the secret.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened secret.</returns>
        public NtResult<LsaSecret> OpenSecret(string name, LsaSecretAccessRights desired_access, bool throw_on_error)
        {
            return SecurityNativeMethods.LsaOpenSecret(Handle, new UnicodeString(name), 
                desired_access, out SafeLsaHandle handle).CreateResult(throw_on_error, () => new LsaSecret(handle, desired_access, name, SystemName));
        }

        /// <summary>
        /// Open an LSA secret object.
        /// </summary>
        /// <param name="name">The name of the secret.</param>
        /// <param name="desired_access">The desired access for the secret.</param>
        /// <returns>The opened secret.</returns>
        public LsaSecret OpenSecret(string name, LsaSecretAccessRights desired_access)
        {
            return OpenSecret(name, desired_access, true).Result;
        }

        /// <summary>
        /// Open an LSA secret object with maximum access.
        /// </summary>
        /// <param name="name">The name of the secret.</param>
        /// <returns>The opened secret.</returns>
        public LsaSecret OpenSecret(string name)
        {
            return OpenSecret(name, LsaSecretAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Create an LSA secret object.
        /// </summary>
        /// <param name="name">The name of the secret.</param>
        /// <param name="desired_access">The desired access for the secret.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The created secret.</returns>
        public NtResult<LsaSecret> CreateSecret(string name, LsaSecretAccessRights desired_access, bool throw_on_error)
        {
            return SecurityNativeMethods.LsaCreateSecret(Handle, new UnicodeString(name),
                desired_access, out SafeLsaHandle handle)
                .CreateResult(throw_on_error, () => new LsaSecret(handle, desired_access, name, SystemName));
        }

        /// <summary>
        /// Create an LSA secret object.
        /// </summary>
        /// <param name="name">The name of the secret.</param>
        /// <param name="desired_access">The desired access for the secret.</param>
        /// <returns>The created secret.</returns>
        public LsaSecret CreateSecret(string name, LsaSecretAccessRights desired_access)
        {
            return CreateSecret(name, desired_access, true).Result;
        }

        /// <summary>
        /// Create an LSA secret object with maximum access.
        /// </summary>
        /// <param name="name">The name of the secret.</param>
        /// <returns>The created secret.</returns>
        public LsaSecret CreateSecret(string name)
        {
            return CreateSecret(name, LsaSecretAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Delete an LSA secret object.
        /// </summary>
        /// <param name="name">The name of the secret.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus DeleteSecret(string name, bool throw_on_error)
        {
            using (var secret = OpenSecret(name, LsaSecretAccessRights.Delete, throw_on_error))
            {
                if (!secret.IsSuccess)
                    return secret.Status;
                return secret.Result.Delete(throw_on_error);
            }
        }

        /// <summary>
        /// Delete an LSA secret object.
        /// </summary>
        /// <param name="name">The name of the secret.</param>
        public void DeleteSecret(string name)
        {
            DeleteSecret(name, true);
        }

        /// <summary>
        /// Open an LSA account object.
        /// </summary>
        /// <param name="sid">The SID of the account.</param>
        /// <param name="desired_access">The desired access for the account.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened account.</returns>
        public NtResult<LsaAccount> OpenAccount(Sid sid, LsaAccountAccessRights desired_access, bool throw_on_error)
        {
            using (var buffer = sid.ToSafeBuffer())
            {
                return SecurityNativeMethods.LsaOpenAccount(Handle, buffer,
                    desired_access, out SafeLsaHandle handle).CreateResult(throw_on_error,
                    () => new LsaAccount(handle, desired_access, sid, SystemName));
            }
        }

        /// <summary>
        /// Open an LSA account object.
        /// </summary>
        /// <param name="sid">The SID of the account.</param>
        /// <param name="desired_access">The desired access for the account.</param>
        /// <returns>The opened account.</returns>
        public LsaAccount OpenAccount(Sid sid, LsaAccountAccessRights desired_access)
        {
            return OpenAccount(sid, desired_access, true).Result;
        }

        /// <summary>
        /// Open an LSA account object with maximum access.
        /// </summary>
        /// <param name="sid">The SID of the account.</param>
        /// <returns>The opened account.</returns>
        public LsaAccount OpenAccount(Sid sid)
        {
            return OpenAccount(sid, LsaAccountAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Create an LSA account object.
        /// </summary>
        /// <param name="sid">The SID of the account.</param>
        /// <param name="desired_access">The desired access for the account.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The created account.</returns>
        public NtResult<LsaAccount> CreateAccount(Sid sid, LsaAccountAccessRights desired_access, bool throw_on_error)
        {
            using (var buffer = sid.ToSafeBuffer())
            {
                return SecurityNativeMethods.LsaCreateAccount(Handle, buffer,
                    desired_access, out SafeLsaHandle handle).CreateResult(throw_on_error,
                    () => new LsaAccount(handle, desired_access, sid, SystemName));
            }
        }

        /// <summary>
        /// Create an LSA account object.
        /// </summary>
        /// <param name="sid">The SID of the account.</param>
        /// <param name="desired_access">The desired access for the account.</param>
        /// <returns>The created account.</returns>
        public LsaAccount CreateAccount(Sid sid, LsaAccountAccessRights desired_access)
        {
            return CreateAccount(sid, desired_access, true).Result;
        }

        /// <summary>
        /// Create an LSA account object with maximum access.
        /// </summary>
        /// <param name="sid">The SID of the account.</param>
        /// <returns>The created account.</returns>
        public LsaAccount CreateAccount(Sid sid)
        {
            return CreateAccount(sid, LsaAccountAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Delete an LSA account object.
        /// </summary>
        /// <param name="sid">The SID of the account.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus DeleteAccount(Sid sid, bool throw_on_error)
        {
            using (var account = OpenAccount(sid, LsaAccountAccessRights.Delete, throw_on_error))
            {
                if (!account.IsSuccess)
                    return account.Status;
                return account.Result.Delete(throw_on_error);
            }
        }

        /// <summary>
        /// Delete an LSA account object.
        /// </summary>
        /// <param name="sid">The SID of the account.</param>
        public void DeleteAccount(Sid sid)
        {
            DeleteAccount(sid, true);
        }

        /// <summary>
        /// Enumerate account SIDs in policy.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of account SIDs.</returns>
        public NtResult<IReadOnlyList<Sid>> EnumerateAccounts(bool throw_on_error)
        {
            return LsaPolicyUtils.LsaEnumerateObjects(Handle, SecurityNativeMethods.LsaEnumerateAccounts, 
                (LSAPR_ACCOUNT_INFORMATION s) => new Sid(s.Sid), throw_on_error);
        }

        /// <summary>
        /// Enumerate account SIDs in policy.
        /// </summary>
        /// <returns>The list of account SIDs.</returns>
        public IReadOnlyList<Sid> EnumerateAccounts()
        {
            return EnumerateAccounts(true).Result;
        }

        /// <summary>
        /// Enumerate and open accessible account objects in policy.
        /// </summary>
        /// <param name="desired_access">The desired access for the opened accounts.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of accessible accounts.</returns>
        public NtResult<IReadOnlyList<LsaAccount>> OpenAccessibleAccounts(LsaAccountAccessRights desired_access, bool throw_on_error)
        {
            return EnumerateAccounts(throw_on_error).Map<IReadOnlyList<LsaAccount>>(e => e.Select(
                s => OpenAccount(s, desired_access, false).GetResultOrDefault()).Where(a => a != null).ToList().AsReadOnly());
        }

        /// <summary>
        /// Enumerate and open accessible account objects in policy.
        /// </summary>
        /// <param name="desired_access">The desired access for the opened accounts.</param>
        public IReadOnlyList<LsaAccount> OpenAccessibleAccounts(LsaAccountAccessRights desired_access)
        {
            return OpenAccessibleAccounts(desired_access, true).Result;
        }

        /// <summary>
        /// Enumerate and open accessible account objects in policy with maximum access.
        /// </summary>
        public IReadOnlyList<LsaAccount> OpenAccessibleAccounts()
        {
            return OpenAccessibleAccounts(LsaAccountAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Enumerate trusted domain information.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of trusted domain information.</returns>
        public NtResult<IReadOnlyList<LsaTrustedDomainInformation>> EnumerateTrustedDomains(bool throw_on_error)
        {
            return LsaPolicyUtils.LsaEnumerateObjects(Handle, SecurityNativeMethods.LsaEnumerateTrustedDomainsEx, 
                (TRUSTED_DOMAIN_INFORMATION_EX s) => new LsaTrustedDomainInformation(s), throw_on_error);
        }

        /// <summary>
        /// Enumerate trusted domain information.
        /// </summary>
        /// <returns>The list of trusted domain information.</returns>
        public IReadOnlyList<LsaTrustedDomainInformation> EnumerateTrustedDomains()
        {
            return EnumerateTrustedDomains(true).Result;
        }

        /// <summary>
        /// Open trusted domain object.
        /// </summary>
        /// <param name="sid">The SID of the trusted domain.</param>
        /// <param name="desired_access">The desired access for the object.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The trusted domain object.</returns>
        public NtResult<LsaTrustedDomain> OpenTrustedDomain(Sid sid, LsaTrustedDomainAccessRights desired_access, bool throw_on_error)
        {
            if (sid is null)
            {
                throw new ArgumentNullException(nameof(sid));
            }

            using (var sid_buffer = sid.ToSafeBuffer())
            {
                return SecurityNativeMethods.LsaOpenTrustedDomain(Handle, sid_buffer,
                    desired_access, out SafeLsaHandle handle).CreateResult(throw_on_error,
                    () => new LsaTrustedDomain(handle, desired_access, null, sid, QueryDomainInfo(sid_buffer), SystemName));
            }
        }

        /// <summary>
        /// Open trusted domain object.
        /// </summary>
        /// <param name="sid">The SID of the trusted domain.</param>
        /// <param name="desired_access">The desired access for the object.</param>
        /// <returns>The trusted domain object.</returns>
        public LsaTrustedDomain OpenTrustedDomain(Sid sid, LsaTrustedDomainAccessRights desired_access)
        {
            return OpenTrustedDomain(sid, desired_access, true).Result;
        }

        /// <summary>
        /// Open trusted domain object.
        /// </summary>
        /// <param name="name">The name of the trusted domain.</param>
        /// <param name="desired_access">The desired access for the object.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The trusted domain object.</returns>
        public NtResult<LsaTrustedDomain> OpenTrustedDomain(string name, LsaTrustedDomainAccessRights desired_access, bool throw_on_error)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException($"'{nameof(name)}' cannot be null or empty.", nameof(name));
            }

            return OpenTrustedDomain(name, null, desired_access, throw_on_error);
        }

        /// <summary>
        /// Open trusted domain object.
        /// </summary>
        /// <param name="name">The name of the trusted domain.</param>
        /// <param name="desired_access">The desired access for the object.</param>
        /// <returns>The trusted domain object.</returns>
        public LsaTrustedDomain OpenTrustedDomain(string name, LsaTrustedDomainAccessRights desired_access)
        {
            return OpenTrustedDomain(name, desired_access, true).Result;
        }

        /// <summary>
        /// Enumerate and open accessible trusted domain objects in policy.
        /// </summary>
        /// <param name="desired_access">The desired access for the opened trusted domains.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of accessible trusted domains.</returns>
        public NtResult<IReadOnlyList<LsaTrustedDomain>> OpenAccessibleTrustedDomains(LsaTrustedDomainAccessRights desired_access, bool throw_on_error)
        {
            return EnumerateTrustedDomains(throw_on_error).Map<IReadOnlyList<LsaTrustedDomain>>(e => e.Select(
                s => OpenTrustedDomain(s.Name, s, desired_access, false).GetResultOrDefault()).Where(a => a != null).ToList().AsReadOnly());
        }

        /// <summary>
        /// Enumerate and open accessible trusted domain objects in policy.
        /// </summary>
        /// <param name="desired_access">The desired access for the opened trusted domains.</param>
        /// <returns>The list of accessible trusted domains.</returns>
        public IReadOnlyList<LsaTrustedDomain> OpenAccessibleTrustedDomains(LsaTrustedDomainAccessRights desired_access)
        {
            return OpenAccessibleTrustedDomains(desired_access, true).Result;
        }

        /// <summary>
        /// Enumerate and open accessible trusted domain objects in policy.
        /// </summary>
        /// <returns>The list of accessible trusted domains.</returns>
        public IReadOnlyList<LsaTrustedDomain> OpenAccessibleTrustedDomains()
        {
            return OpenAccessibleTrustedDomains(LsaTrustedDomainAccessRights.MaximumAllowed);
        }

        #endregion

        #region Static Methods
        /// <summary>
        /// Open an LSA policy.
        /// </summary>
        /// <param name="system_name">The system name for the LSA.</param>
        /// <param name="desired_access">The desired access on the policy.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened policy.</returns>
        public static NtResult<LsaPolicy> Open(string system_name, LsaPolicyAccessRights desired_access, bool throw_on_error)
        {
            UnicodeString str = !string.IsNullOrEmpty(system_name) ? new UnicodeString(system_name) : null;

            return SecurityNativeMethods.LsaOpenPolicy(str, new ObjectAttributes(),
                desired_access, out SafeLsaHandle policy).CreateResult(throw_on_error, () => new LsaPolicy(policy, desired_access, system_name));
        }

        /// <summary>
        /// Open an LSA policy.
        /// </summary>
        /// <param name="desired_access">The desired access on the policy.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The opened policy.</returns>
        public static NtResult<LsaPolicy> Open(LsaPolicyAccessRights desired_access, bool throw_on_error)
        {
            return Open(null, desired_access, throw_on_error);
        }

        /// <summary>
        /// Open an LSA policy.
        /// </summary>
        /// <param name="system_name">The system name for the LSA.</param>
        /// <param name="desired_access">The desired access on the policy.</param>
        /// <returns>The opened policy.</returns>
        public static LsaPolicy Open(string system_name, LsaPolicyAccessRights desired_access)
        {
            return Open(system_name, desired_access, true).Result;
        }

        /// <summary>
        /// Open an LSA policy.
        /// </summary>
        /// <param name="desired_access">The desired access on the policy.</param>
        /// <returns>The opened policy.</returns>
        public static LsaPolicy Open(LsaPolicyAccessRights desired_access)
        {
            return Open(null, desired_access);
        }

        /// <summary>
        /// Open an LSA policy with maximum allowed access.
        /// </summary>
        /// <returns>The opened policy.</returns>
        public static LsaPolicy Open()
        {
            return Open(LsaPolicyAccessRights.MaximumAllowed);
        }
        #endregion
    }
}
