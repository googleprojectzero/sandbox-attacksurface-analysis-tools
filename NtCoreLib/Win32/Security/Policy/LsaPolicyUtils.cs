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

namespace NtApiDotNet.Win32.Security.Policy
{
    /// <summary>
    /// Utilities for an LSA policy.
    /// </summary>
    internal static class LsaPolicyUtils
    {
        #region Internal Methods
        internal static UnicodeStringBytesSafeBuffer ToUnicodeStringBuffer(this byte[] data)
        {
            if (data == null)
            {
                return UnicodeStringBytesSafeBuffer.Null;
            }
            return new UnicodeStringBytesSafeBuffer(data);
        }
        #endregion

        #region Static Methods
        /// <summary>
        /// The name of the fake NT type for a LSA policy.
        /// </summary>
        public const string LSA_POLICY_NT_TYPE_NAME = "LsaPolicy";

        /// <summary>
        /// The name of the fake NT type for a LSA secret.
        /// </summary>
        public const string LSA_SECRET_NT_TYPE_NAME = "LsaSecret";

        /// <summary>
        /// The name of the fake NT type for a LSA account.
        /// </summary>
        public const string LSA_ACCOUNT_NT_TYPE_NAME = "LsaAccount";

        /// <summary>
        /// The name of the fake NT type for a LSA trusted domain.
        /// </summary>
        public const string LSA_TRUSTED_DOMAIN_NT_TYPE_NAME = "LsaTrustedDomain";

        /// <summary>
        /// Generic generic mapping for LSA policy security.
        /// </summary>
        /// <returns>The generic mapping for the LSA policy.</returns>
        public static GenericMapping GetLsaPolicyGenericMapping()
        {
            return new GenericMapping()
            {
                GenericRead = LsaPolicyAccessRights.ReadControl | LsaPolicyAccessRights.ViewAuditInformation | LsaPolicyAccessRights.GetPrivateInformation,
                GenericWrite = LsaPolicyAccessRights.ReadControl | LsaPolicyAccessRights.TrustAdmin | LsaPolicyAccessRights.CreateAccount | LsaPolicyAccessRights.CreateSecret |
                    LsaPolicyAccessRights.CreatePrivilege | LsaPolicyAccessRights.SetDefaultQuotaLimits | LsaPolicyAccessRights.SetAuditRequirements | LsaPolicyAccessRights.AuditLogAdmin |
                    LsaPolicyAccessRights.ServerAdmin,
                GenericExecute = LsaPolicyAccessRights.ReadControl | LsaPolicyAccessRights.ViewLocalInformation | LsaPolicyAccessRights.LookupNames,
                GenericAll = LsaPolicyAccessRights.ReadControl | LsaPolicyAccessRights.WriteDac | LsaPolicyAccessRights.WriteOwner | LsaPolicyAccessRights.Delete |
                    LsaPolicyAccessRights.ViewAuditInformation | LsaPolicyAccessRights.GetPrivateInformation | LsaPolicyAccessRights.TrustAdmin | LsaPolicyAccessRights.CreateAccount | LsaPolicyAccessRights.CreateSecret |
                    LsaPolicyAccessRights.CreatePrivilege | LsaPolicyAccessRights.SetDefaultQuotaLimits | LsaPolicyAccessRights.SetAuditRequirements | LsaPolicyAccessRights.AuditLogAdmin |
                    LsaPolicyAccessRights.ServerAdmin | LsaPolicyAccessRights.ViewLocalInformation | LsaPolicyAccessRights.LookupNames | LsaPolicyAccessRights.Notification
            };
        }

        /// <summary>
        /// Generic generic mapping for LSA secret security.
        /// </summary>
        /// <returns>The generic mapping for the LSA secret.</returns>
        public static GenericMapping GetLsaSecretGenericMapping()
        {
            return new GenericMapping()
            {
                GenericRead = LsaSecretAccessRights.ReadControl | LsaSecretAccessRights.QueryValue,
                GenericWrite = LsaSecretAccessRights.ReadControl | LsaSecretAccessRights.SetValue,
                GenericExecute = LsaPolicyAccessRights.ReadControl,
                GenericAll = LsaSecretAccessRights.ReadControl | LsaSecretAccessRights.WriteDac | LsaSecretAccessRights.WriteOwner | LsaSecretAccessRights.Delete |
                    LsaSecretAccessRights.QueryValue | LsaSecretAccessRights.SetValue
            };
        }

        /// <summary>
        /// Generic generic mapping for LSA account security.
        /// </summary>
        /// <returns>The generic mapping for the LSA account.</returns>
        public static GenericMapping GetLsaAccountGenericMapping()
        {
            return new GenericMapping()
            {
                GenericRead = LsaAccountAccessRights.ReadControl | LsaAccountAccessRights.View,
                GenericWrite = LsaAccountAccessRights.ReadControl | LsaAccountAccessRights.AdjustPrivileges | LsaAccountAccessRights.AdjustQuotas | LsaAccountAccessRights.AdjustSystemAccess,
                GenericExecute = LsaAccountAccessRights.ReadControl,
                GenericAll = LsaAccountAccessRights.ReadControl | LsaAccountAccessRights.WriteDac | LsaAccountAccessRights.WriteOwner | LsaAccountAccessRights.Delete |
                    LsaAccountAccessRights.View | LsaAccountAccessRights.AdjustPrivileges | LsaAccountAccessRights.AdjustQuotas | LsaAccountAccessRights.AdjustSystemAccess
            };
        }

        /// <summary>
        /// Generic generic mapping for LSA trusted domain security.
        /// </summary>
        /// <returns>The generic mapping for the LSA trusted domain.</returns>
        public static GenericMapping GetLsaTrustedDomainGenericMapping()
        {
            return new GenericMapping()
            {
                GenericRead = LsaTrustedDomainAccessRights.ReadControl | LsaTrustedDomainAccessRights.QueryDomainName,
                GenericWrite = LsaTrustedDomainAccessRights.ReadControl | LsaTrustedDomainAccessRights.SetControllers | LsaTrustedDomainAccessRights.SetPosix,
                GenericExecute = LsaTrustedDomainAccessRights.ReadControl | LsaTrustedDomainAccessRights.QueryControllers | LsaTrustedDomainAccessRights.QueryPosix,
                GenericAll = LsaTrustedDomainAccessRights.ReadControl | LsaTrustedDomainAccessRights.WriteDac | LsaTrustedDomainAccessRights.WriteOwner | LsaTrustedDomainAccessRights.Delete |
                    LsaTrustedDomainAccessRights.QueryDomainName | LsaTrustedDomainAccessRights.SetControllers | LsaTrustedDomainAccessRights.SetPosix | LsaTrustedDomainAccessRights.SetAuth |
                    LsaTrustedDomainAccessRights.QueryControllers | LsaTrustedDomainAccessRights.QueryPosix | LsaTrustedDomainAccessRights.QueryAuth
            };
        }

        public static NtType LsaPolicyNtType => NtType.GetTypeByName(LSA_POLICY_NT_TYPE_NAME);
        public static NtType LsaSecretNtType => NtType.GetTypeByName(LSA_SECRET_NT_TYPE_NAME);
        public static NtType LsaAccountNtType => NtType.GetTypeByName(LSA_ACCOUNT_NT_TYPE_NAME);
        public static NtType LsaTrustedDomainNtType => NtType.GetTypeByName(LSA_TRUSTED_DOMAIN_NT_TYPE_NAME);

        public static NtResult<IReadOnlyList<T>> LsaEnumerateObjects<T, S>(SafeLsaHandle handle, 
                SecurityEnumDelegate<SafeLsaHandle, SafeLsaMemoryBuffer> func, Func<S, T> select_object,
                bool throw_on_error) where S : struct
        {
            return SecurityNativeMethods.EnumerateObjects(handle, func, select_object, throw_on_error);
        }

        #endregion
    }
}
