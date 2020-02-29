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
using System.Linq;

namespace NtApiDotNet
{
    /// <summary>
    /// The result of a privilege check.
    /// </summary>
    public class PrivilegeCheckResult
    {
        /// <summary>
        /// The list of privileges from the result.
        /// </summary>
        public IEnumerable<TokenPrivilege> Privileges { get; }
        /// <summary>
        /// The list of enabled privileges.
        /// </summary>
        public IEnumerable<TokenPrivilege> EnabledPrivileges => Privileges.Where(p => p.UsedForAccess);
        /// <summary>
        /// True indicates all privileges were held.
        /// </summary>
        public bool AllPrivilegesHeld { get; }

        internal PrivilegeCheckResult(IEnumerable<TokenPrivilege> privileges, bool all_privileges_held)
        {
            Privileges = privileges;
            AllPrivilegesHeld = all_privileges_held;
        }

        internal PrivilegeCheckResult(SafePrivilegeSetBuffer privileges, bool all_privileges_held)
        {
            var result = privileges.Result;
            LuidAndAttributes[] luids = new LuidAndAttributes[result.PrivilegeCount];
            privileges.Data.ReadArray(0, luids, 0, luids.Length);
            Privileges = luids.Select(l => new TokenPrivilege(l.Luid, l.Attributes)).ToList().AsReadOnly();
            AllPrivilegesHeld = all_privileges_held;
        }
    }
}
