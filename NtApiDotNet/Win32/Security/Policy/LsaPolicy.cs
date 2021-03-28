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

using NtApiDotNet.Security;
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
    public sealed class LsaPolicy : IDisposable, INtObjectSecurity
    {
        #region Private Members
        private readonly LsaPolicyAccessRights _granted_access;
        private readonly SafeLsaHandle _handle;
        private readonly string _system_name;
        private delegate NtStatus LookupSidsDelegate(IntPtr[] sid_ptrs, out SafeLsaMemoryBuffer domains, out SafeLsaMemoryBuffer names);

        private LsaPolicy(SafeLsaHandle handle, LsaPolicyAccessRights granted_access, string system_name)
        {
            _handle = handle;
            _granted_access = LsaPolicyUtils.GetLsaPolicyGenericMapping().MapMask(granted_access).ToSpecificAccess<LsaPolicyAccessRights>();
            _system_name = system_name;
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
                => SecurityNativeMethods.LsaLookupSids(_handle, s.Length, s, out d, out n), throw_on_error);
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
        /// Lookup names for SIDs.
        /// </summary>
        /// <param name="sids">The list of SIDs to lookup.</param>
        /// <param name="options">Lookup options flags.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of looked up SID names.</returns>
        [SupportedVersion(SupportedVersion.Windows8)]
        public NtResult<IReadOnlyList<SidName>> LookupSids2(IEnumerable<Sid> sids, LsaLookupOptionFlags options, bool throw_on_error)
        {
            if (NtObjectUtils.IsWindows7OrLess)
                throw new NotSupportedException($"{nameof(LookupSids2)} isn't supported until Windows 8");

            return LookupSids(sids, (IntPtr[] s, out SafeLsaMemoryBuffer d, out SafeLsaMemoryBuffer n) 
                => SecurityNativeMethods.LsaLookupSids2(_handle, options, s.Length, s, out d, out n), throw_on_error);
        }

        /// <summary>
        /// Lookup names for SIDs.
        /// </summary>
        /// <param name="sids">The list of SIDs to lookup.</param>
        /// <param name="options">Lookup options flags.</param>
        /// <returns>The list of looked up SID names.</returns>
        [SupportedVersion(SupportedVersion.Windows8)]
        public IReadOnlyList<SidName> LookupSids2(IEnumerable<Sid> sids, LsaLookupOptionFlags options)
        {
            return LookupSids2(sids, options, true).Result;
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

            NtStatus status = SecurityNativeMethods.LsaEnumerateAccountsWithUserRight(_handle, 
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
                return SecurityNativeMethods.LsaEnumerateAccountRights(_handle, sid_buffer,
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

        #endregion

        #region INtObjectSecurity Implementation
        NtType INtObjectSecurity.NtType => NtType.GetTypeByName(LsaPolicyUtils.LSA_POLICY_NT_TYPE_NAME);

        string INtObjectSecurity.ObjectName => string.IsNullOrEmpty(_system_name) ? "LSA Policy" : $@"LSA Policy (\\{_system_name}";

        bool INtObjectSecurity.IsAccessMaskGranted(AccessMask access)
        {
            // We can't tell if we really have access or not, so just assume we do.
            if (_granted_access.HasFlagSet(LsaPolicyAccessRights.MaximumAllowed))
                return true;
            return _granted_access.HasFlagAllSet(access.ToSpecificAccess<LsaPolicyAccessRights>());
        }

        /// <summary>
        /// Get the security descriptor specifying which parts to retrieve
        /// </summary>
        /// <param name="security_information">What parts of the security descriptor to retrieve</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The security descriptor</returns>
        public NtResult <SecurityDescriptor> GetSecurityDescriptor(SecurityInformation security_information, bool throw_on_error)
        {
            return _handle.QuerySecurity(security_information, LsaPolicyUtils.LsaPolicyNtType, throw_on_error);
        }

        /// <summary>
        /// Get the security descriptor specifying which parts to retrieve
        /// </summary>
        /// <param name="security_information">What parts of the security descriptor to retrieve</param>
        /// <returns>The security descriptor</returns>
        public SecurityDescriptor GetSecurityDescriptor(SecurityInformation security_information)
        {
            return GetSecurityDescriptor(security_information, true).Result;
        }

        /// <summary>
        /// Set the object's security descriptor
        /// </summary>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="security_information">What parts of the security descriptor to set</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public NtStatus SetSecurityDescriptor(SecurityDescriptor security_descriptor, SecurityInformation security_information, bool throw_on_error)
        {
            return _handle.SetSecurity(security_information, security_descriptor, throw_on_error);
        }

        /// <summary>
        /// Set the object's security descriptor
        /// </summary>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="security_information">What parts of the security descriptor to set</param>
        public void SetSecurityDescriptor(SecurityDescriptor security_descriptor, SecurityInformation security_information)
        {
            SetSecurityDescriptor(security_descriptor, security_information, true);
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

        #region IDisposable implementation.
        /// <summary>
        /// Dispose the policy.
        /// </summary>
        public void Dispose()
        {
            ((IDisposable)_handle).Dispose();
        }
        #endregion
    }
}
