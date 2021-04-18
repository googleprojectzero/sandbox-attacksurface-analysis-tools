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
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Policy
{
    /// <summary>
    /// Class to represent an LSA account object.
    /// </summary>
    public sealed class LsaAccount : LsaObject
    {
        #region Private Members
        private IReadOnlyList<TokenPrivilege> GetPrivileges(SafeLsaMemoryBuffer buffer)
        {
            using (buffer)
            {
                buffer.Initialize<PrivilegeSet>(1);
                SafePrivilegeSetBuffer priv_set = new SafePrivilegeSetBuffer(buffer.DangerousGetHandle(), buffer.Read<PrivilegeSet>(0).PrivilegeCount);
                return priv_set.GetPrivileges(SystemName).ToList().AsReadOnly();
            }
        }
        #endregion

        #region Internal Members
        internal LsaAccount(SafeLsaHandle handle, LsaAccountAccessRights granted_access, Sid sid, string system_name)
            : base(handle, granted_access, LsaPolicyUtils.LSA_ACCOUNT_NT_TYPE_NAME, $"LSA Account ({sid})", system_name)
        {
            Sid = sid;
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Get the account SID.
        /// </summary>
        public Sid Sid { get; }

        /// <summary>
        /// Get or set system access flags.
        /// </summary>
        public LsaSystemAccessFlags SystemAccess
        {
            get => GetSystemAccess(true).Result;
            set => SetSystemAccess(value, true);
        }

        /// <summary>
        /// Get account privileges.
        /// </summary>
        public IReadOnlyList<TokenPrivilege> Privileges => EnumeratePrivileges(true).Result;

        #endregion

        #region Public Methods

        /// <summary>
        /// Get system access flags.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The system access flags.</returns>
        public NtResult<LsaSystemAccessFlags> GetSystemAccess(bool throw_on_error)
        {
            return SecurityNativeMethods.LsaGetSystemAccessAccount(Handle, 
                out LsaSystemAccessFlags flags).CreateResult(throw_on_error, () => flags);
        }

        /// <summary>
        /// Set system access flags.
        /// </summary>
        /// <param name="flags">The flags to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The system access flags.</returns>
        public NtStatus SetSystemAccess(LsaSystemAccessFlags flags, bool throw_on_error)
        {
            return SecurityNativeMethods.LsaSetSystemAccessAccount(Handle,
                flags).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Enumerate privileges for the account.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of token privileges.</returns>
        public NtResult<IReadOnlyList<TokenPrivilege>> EnumeratePrivileges(bool throw_on_error)
        {
            return SecurityNativeMethods.LsaEnumeratePrivilegesOfAccount(Handle, 
                out SafeLsaMemoryBuffer privileges).CreateResult(throw_on_error, () => GetPrivileges(privileges));
        }

        #endregion
    }
}
