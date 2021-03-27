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
using System;

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

        private LsaPolicy(SafeLsaHandle handle, LsaPolicyAccessRights granted_access)
        {
            _handle = handle;
            _granted_access = LsaPolicyUtils.GetLsaPolicyGenericMapping().MapMask(granted_access).ToSpecificAccess<LsaPolicyAccessRights>();
        }
        #endregion

        #region INtObjectSecurity Implementation
        NtType INtObjectSecurity.NtType => NtType.GetTypeByName(LsaPolicyUtils.LSA_POLICY_NT_TYPE_NAME);

        string INtObjectSecurity.ObjectName => "LSA Policy";

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
            return SafeLsaHandle.OpenPolicy(system_name, desired_access, throw_on_error).Map(h => new LsaPolicy(h, desired_access));
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
