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
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Audit
{
    /// <summary>
    /// System Audit Category.
    /// </summary>
    public class AuditCategory
    {
        /// <summary>
        /// The ID of the category.
        /// </summary>
        public Guid Id { get; }

        /// <summary>
        /// The name of the category.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// List of sub categories.
        /// </summary>
        public IReadOnlyList<AuditSubCategory> SubCategories { get; }

        /// <summary>
        /// Convert to string.
        /// </summary>
        /// <returns>The name of the category.</returns>
        public override string ToString() => Name;

        /// <summary>
        /// Set audit policy on all sub categories.
        /// </summary>
        /// <param name="flags">The flags to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The audit policy flags.</returns>
        public NtStatus SetPolicy(AuditPolicyFlags flags, bool throw_on_error)
        {
            AUDIT_POLICY_INFORMATION[] policies = SubCategories.Select(c => new AUDIT_POLICY_INFORMATION()
            {
                AuditSubCategoryGuid = c.Id,
                AuditingInformation = (int)flags
            }).ToArray();
            if (!Win32NativeMethods.AuditSetSystemPolicy(policies, policies.Length))
                return NtObjectUtils.MapDosErrorToStatus();
            return NtStatus.STATUS_SUCCESS;
        }

        /// <summary>
        /// Set audit policy on all sub categories.
        /// </summary>
        /// <param name="flags">The flags to set.</param>
        /// <returns>The audit policy flags.</returns>
        public void SetPolicy(AuditPolicyFlags flags)
        {
            SetPolicy(flags, true);
        }

        internal AuditCategory(Guid id, string name)
        {
            Id = id;
            Name = name;
            SubCategories = AuditSubCategory.GetSubCategories(this, false)
                .GetResultOrDefault(new List<AuditSubCategory>()).AsReadOnly();
        }

        private static NtResult<string> LookupCategoryName(Guid category, bool throw_on_error)
        {
            return Win32NativeMethods.AuditLookupCategoryName(ref category,
                out SafeAuditBuffer buffer).CreateWin32Result(throw_on_error, () => {
                    using (buffer)
                    {
                        return Marshal.PtrToStringUni(buffer.DangerousGetHandle());
                    }
                });
        }

        private static AuditCategory[] GetCategories(SafeAuditBuffer buffer, uint count)
        {
            using (buffer)
            {
                List<AuditCategory> categories = new List<AuditCategory>();
                buffer.Initialize<Guid>(count);
                Guid[] cats = new Guid[count];
                buffer.ReadArray(0, cats, 0, (int)count);

                foreach (Guid cat in cats)
                {
                    var name = LookupCategoryName(cat, false).GetResultOrDefault(cat.ToString());
                    categories.Add(new AuditCategory(cat, name));
                }
                return categories.ToArray();
            }
        }

        /// <summary>
        /// Get list of Audit Policy categories.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of categories.</returns>
        internal static NtResult<AuditCategory[]> GetCategories(bool throw_on_error)
        {
            return Win32NativeMethods.AuditEnumerateCategories(out SafeAuditBuffer buffer, 
                out uint count).CreateWin32Result(throw_on_error, () => GetCategories(buffer, count));
        }

        internal static NtResult<AuditCategory> GetCategory(Guid category, bool throw_on_error)
        {
            return LookupCategoryName(category, throw_on_error).Map(s => new AuditCategory(category, s));
        }

        internal static NtResult<AuditCategory> GetCategory(AuditPolicyEventType type, bool throw_on_error)
        {
            if (!Win32NativeMethods.AuditLookupCategoryGuidFromCategoryId(type, out Guid category))
                return NtObjectUtils.MapDosErrorToStatus().CreateResultFromError<AuditCategory>(throw_on_error);
            return GetCategory(category, throw_on_error);
        }
    }
}
