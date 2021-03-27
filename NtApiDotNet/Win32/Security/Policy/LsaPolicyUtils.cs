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

namespace NtApiDotNet.Win32.Security.Policy
{
    /// <summary>
    /// Utilities for an LSA policy.
    /// </summary>
    internal static class LsaPolicyUtils
    {
        #region Static Methods
        /// <summary>
        /// The name of the fake NT type for a LSA policy.
        /// </summary>
        public const string LSA_POLICY_NT_TYPE_NAME = "LsaPolicy";

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

        public static NtType LsaPolicyNtType => NtType.GetTypeByName(LSA_POLICY_NT_TYPE_NAME);

        #endregion
    }
}
