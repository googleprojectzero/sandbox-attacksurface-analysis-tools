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

namespace NtApiDotNet.Win32.Security.Audit
{
    /// <summary>
    /// Class representing an Audit Sub Category.
    /// </summary>
    public sealed class AuditSubCategory : AuditSubCategory<AuditPolicyFlags>
    {
        /// <summary>
        /// The category.
        /// </summary>
        public AuditCategory Category { get; }

        internal AuditSubCategory(Guid id, string name, AuditCategory category) 
            : base(id, name)
        {
            Category = category;
        }

        private protected override Win32Error SetPolicy(AUDIT_POLICY_INFORMATION[] policies)
        {
            return SecurityNativeMethods.AuditSetSystemPolicy(policies, policies.Length).GetLastWin32Error();
        }

        private protected override Win32Error QueryPolicy(Guid[] system_policies, out SafeAuditBuffer buffer)
        {
            return SecurityNativeMethods.AuditQuerySystemPolicy(system_policies, system_policies.Length, out buffer).GetLastWin32Error();
        }
    }

    /// <summary>
    /// Class representing an Audit Sub Category.
    /// </summary>
    public sealed class AuditPerUserSubCategory : AuditSubCategory<AuditPerUserPolicyFlags>
    {
        /// <summary>
        /// The category.
        /// </summary>
        public AuditPerUserCategory Category { get; }

        /// <summary>
        /// The user for the per-user category.
        /// </summary>
        public Sid User { get; }

        internal AuditPerUserSubCategory(Guid id, string name, AuditPerUserCategory category, Sid user)
            : base(id, name)
        {
            Category = category;
            User = user;
        }

        private protected override Win32Error SetPolicy(AUDIT_POLICY_INFORMATION[] policies)
        {
            using (var buffer = User.ToSafeBuffer())
            {
                return SecurityNativeMethods.AuditSetPerUserPolicy(buffer, policies, policies.Length).GetLastWin32Error();
            }
        }

        private protected override Win32Error QueryPolicy(Guid[] system_policies, out SafeAuditBuffer buffer)
        {
            using (var sid_buffer = User.ToSafeBuffer())
            {
                return SecurityNativeMethods.AuditQueryPerUserPolicy(sid_buffer, 
                    system_policies, system_policies.Length, out buffer).GetLastWin32Error();
            }
        }
    }

    /// <summary>
    /// Class representing an Audit Sub Category. Base class.
    /// </summary>
    /// <typeparam name="T">Enum type for the Policy flags.</typeparam>
    public abstract class AuditSubCategory<T> where T : Enum
    {
        /// <summary>
        /// The ID of the sub category.
        /// </summary>
        public Guid Id { get; set; }
        /// <summary>
        /// The name of the sub category.
        /// </summary>
        public string Name { get; set; }
        /// <summary>
        /// The Current Audit Policy
        /// </summary>
        public T Policy => QueryPolicy(false).GetResultOrDefault(default);
        /// <summary>
        /// Convert to string.
        /// </summary>
        /// <returns>The name of the subcategory.</returns>
        public override string ToString() => Name;

        /// <summary>
        /// Query audit policy.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The audit policy flags.</returns>
        public NtResult<T> QueryPolicy(bool throw_on_error)
        {
            return QueryPolicy(new Guid[] { Id }, out SafeAuditBuffer buffer)
                .CreateWin32Result(throw_on_error, () => GetPolicy(buffer));
        }

        private protected abstract Win32Error QueryPolicy(Guid[] system_policies, out SafeAuditBuffer buffer);
        private protected abstract Win32Error SetPolicy(AUDIT_POLICY_INFORMATION[] policies);

        /// <summary>
        /// Set audit policy.
        /// </summary>
        /// <param name="flags">The flags to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The audit policy flags.</returns>
        public NtStatus SetPolicy(T flags, bool throw_on_error)
        {
            AUDIT_POLICY_INFORMATION[] policies = new AUDIT_POLICY_INFORMATION[1] { 
                new AUDIT_POLICY_INFORMATION() { AuditSubCategoryGuid = Id, AuditingInformation = Convert.ToInt32(flags) } };
            return SetPolicy(policies).MapDosErrorToStatus().ToNtException(throw_on_error);
        }

        /// <summary>
        /// Set audit policy.
        /// </summary>
        /// <param name="flags">The flags to set.</param>
        /// <returns>The audit policy flags.</returns>
        public void SetPolicy(T flags)
        {
            SetPolicy(flags, true);
        }

        internal AuditSubCategory(Guid id, string name)
        {
            Id = id;
            Name = name;
        }

        private static T GetPolicy(SafeAuditBuffer buffer)
        {
            if (buffer.IsInvalid)
                return default;
            using (buffer)
            {
                buffer.Initialize<AUDIT_POLICY_INFORMATION>(1);
                return (T)(object)buffer.Read<AUDIT_POLICY_INFORMATION>(0).AuditingInformation;
            }
        }
    }
}
