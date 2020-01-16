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

using System.Collections.Generic;

namespace NtApiDotNet
{
    /// <summary>
    /// Result of an access check.
    /// </summary>
    public class AccessCheckResult
    {
        /// <summary>
        /// The NT status code from the access check.
        /// </summary>
        public NtStatus Status { get; }
        /// <summary>
        /// The granted access from the check.
        /// </summary>
        public AccessMask GrantedAccess { get; }
        /// <summary>
        /// The required privileges for this access.
        /// </summary>
        public IEnumerable<TokenPrivilege> PrivilegesRequired { get; }

        internal AccessCheckResult(NtStatus status, AccessMask granted_access, SafePrivilegeSetBuffer privilege_set)
        {
            Status = status;
            GrantedAccess = granted_access;
            PrivilegesRequired = privilege_set?.GetPrivileges() ?? new TokenPrivilege[0];
        }
    }
}