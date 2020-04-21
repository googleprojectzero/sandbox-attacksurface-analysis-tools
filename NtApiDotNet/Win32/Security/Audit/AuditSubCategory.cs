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
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Audit
{
    /// <summary>
    /// Class representing an Audit Sub Category.
    /// </summary>
    public class AuditSubCategory
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
        /// The category.
        /// </summary>
        public AuditCategory Category { get; }
        /// <summary>
        /// The Current Audit Policy
        /// </summary>
        public AuditPolicyFlags Policy => QueryPolicy(false).GetResultOrDefault(AuditPolicyFlags.Unchanged);

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
        public NtResult<AuditPolicyFlags> QueryPolicy(bool throw_on_error)
        {
            return Win32NativeMethods.AuditQuerySystemPolicy(new Guid[] { Id },
                1, out SafeAuditBuffer buffer).CreateWin32Result(throw_on_error, () => GetPolicy(buffer));
        }

        /// <summary>
        /// Set audit policy.
        /// </summary>
        /// <param name="flags">The flags to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The audit policy flags.</returns>
        public NtStatus SetPolicy(AuditPolicyFlags flags, bool throw_on_error)
        {
            AUDIT_POLICY_INFORMATION[] policies = new AUDIT_POLICY_INFORMATION[1] { 
                new AUDIT_POLICY_INFORMATION() { AuditSubCategoryGuid = Id, AuditingInformation = (int)flags } };
            if (!Win32NativeMethods.AuditSetSystemPolicy(policies, 1))
                return NtObjectUtils.MapDosErrorToStatus();
            return NtStatus.STATUS_SUCCESS;
        }

        /// <summary>
        /// Set audit policy.
        /// </summary>
        /// <param name="flags">The flags to set.</param>
        /// <returns>The audit policy flags.</returns>
        public void SetPolicy(AuditPolicyFlags flags)
        {
            SetPolicy(flags, true);
        }

        internal AuditSubCategory(Guid id, string name, AuditCategory category)
        {
            Id = id;
            Name = name;
            Category = category;
        }

        private static AuditPolicyFlags GetPolicy(SafeAuditBuffer buffer)
        {
            if (buffer.IsInvalid)
                return AuditPolicyFlags.None;
            using (buffer)
            {
                buffer.Initialize<AUDIT_POLICY_INFORMATION>(1);
                return (AuditPolicyFlags)buffer.Read<AUDIT_POLICY_INFORMATION>(0).AuditingInformation;
            }
        }

        private static NtResult<string> LookupSubCategoryName(Guid id, bool throw_on_error)
        {
            return Win32NativeMethods.AuditLookupSubCategoryName(ref id,
                out SafeAuditBuffer buffer).CreateWin32Result(throw_on_error, () => {
                    using (buffer)
                    {
                        return Marshal.PtrToStringUni(buffer.DangerousGetHandle());
                    }
                });
        }

        private static List<AuditSubCategory> GetSubCategories(SafeAuditBuffer buffer, uint count, AuditCategory category)
        {
            using (buffer)
            {
                List<AuditSubCategory> categories = new List<AuditSubCategory>();
                buffer.Initialize<Guid>(count);
                Guid[] cats = new Guid[count];
                buffer.ReadArray(0, cats, 0, (int)count);

                foreach (Guid cat in cats)
                {
                    var name = LookupSubCategoryName(cat, false).GetResultOrDefault(cat.ToString());
                    categories.Add(new AuditSubCategory(cat, name, category));
                }
                return categories;
            }
        }

        internal static NtResult<List<AuditSubCategory>> GetSubCategories(AuditCategory category, bool throw_on_error)
        {
            return Win32NativeMethods.AuditEnumerateSubCategories(category.Id, false,
                out SafeAuditBuffer buffer, out uint count)
                .CreateWin32Result(throw_on_error, () => GetSubCategories(buffer, count, category));
        }
    }
}
