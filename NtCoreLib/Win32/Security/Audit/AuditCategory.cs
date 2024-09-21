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
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Audit
{
    /// <summary>
    /// System Audit Category.
    /// </summary>
    public class AuditCategory : AuditCategory<AuditPolicyFlags, AuditSubCategory>
    {
        internal AuditCategory(Guid id, string name) : base(id, name, CreateSubCategory)
        {
        }

        private static AuditSubCategory CreateSubCategory(Guid id, string name, 
            AuditCategory<AuditPolicyFlags, AuditSubCategory> category)
        {
            return new AuditSubCategory(id, name, (AuditCategory)category);
        }

        private protected override Win32Error SetPolicy(AUDIT_POLICY_INFORMATION[] policies)
        {
            return SecurityNativeMethods.AuditSetSystemPolicy(policies, policies.Length).GetLastWin32Error();
        }
    }

    /// <summary>
    /// System Audit Category.
    /// </summary>
    public class AuditPerUserCategory : AuditCategory<AuditPerUserPolicyFlags, AuditPerUserSubCategory>
    {
        /// <summary>
        /// The user for the per-user category.
        /// </summary>
        public Sid User { get; }

        internal AuditPerUserCategory(Guid id, string name, Sid user) 
            : base(id, name, (i, n, c) => CreateSubCategory(i, n, c, user))
        {
            User = user;
        }

        private static AuditPerUserSubCategory CreateSubCategory(Guid id, string name, 
            AuditCategory<AuditPerUserPolicyFlags, AuditPerUserSubCategory> category, Sid user)
        {
            return new AuditPerUserSubCategory(id, name, (AuditPerUserCategory)category, user);
        }

        private protected override Win32Error SetPolicy(AUDIT_POLICY_INFORMATION[] policies)
        {
            return SecurityNativeMethods.AuditSetSystemPolicy(policies, policies.Length).GetLastWin32Error();
        }
    }

    /// <summary>
    /// System Audit Category base class.
    /// </summary>
    public abstract class AuditCategory<T, S> where T : Enum where S : AuditSubCategory<T>
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
        public IReadOnlyList<S> SubCategories { get; }

        /// <summary>
        /// Convert to string.
        /// </summary>
        /// <returns>The name of the category.</returns>
        public override string ToString() => Name;

        private protected abstract Win32Error SetPolicy(AUDIT_POLICY_INFORMATION[] policies);

        /// <summary>
        /// Set audit policy on all sub categories.
        /// </summary>
        /// <param name="flags">The flags to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The audit policy flags.</returns>
        public NtStatus SetPolicy(T flags, bool throw_on_error)
        {
            AUDIT_POLICY_INFORMATION[] policies = SubCategories.Select(c => new AUDIT_POLICY_INFORMATION()
            {
                AuditSubCategoryGuid = c.Id,
                AuditingInformation = Convert.ToInt32(flags)
            }).ToArray();
            return SetPolicy(policies).MapDosErrorToStatus().ToNtException(throw_on_error);
        }

        /// <summary>
        /// Set audit policy on all sub categories.
        /// </summary>
        /// <param name="flags">The flags to set.</param>
        /// <returns>The audit policy flags.</returns>
        public void SetPolicy(T flags)
        {
            SetPolicy(flags, true);
        }

        internal AuditCategory(Guid id, string name, Func<Guid, string, AuditCategory<T, S>, S> create_sub_category)
        {
            Id = id;
            Name = name;
            SubCategories = GetSubCategories(create_sub_category, false)
                .GetResultOrDefault(new List<S>()).AsReadOnly();
        }

        private static NtResult<string> LookupSubCategoryName(Guid id, bool throw_on_error)
        {
            return SecurityNativeMethods.AuditLookupSubCategoryName(ref id,
                out SafeAuditBuffer buffer).CreateWin32Result(throw_on_error, () => {
                    using (buffer)
                    {
                        return Marshal.PtrToStringUni(buffer.DangerousGetHandle());
                    }
                });
        }

        private List<S> GetSubCategories(SafeAuditBuffer buffer, uint count, Func<Guid, string, AuditCategory<T, S>, S> create_sub_category)
        {
            using (buffer)
            {
                List<S> categories = new List<S>();
                buffer.Initialize<Guid>(count);
                Guid[] cats = new Guid[count];
                buffer.ReadArray(0, cats, 0, (int)count);

                foreach (Guid cat in cats)
                {
                    var name = LookupSubCategoryName(cat, false).GetResultOrDefault(cat.ToString());
                    categories.Add(create_sub_category(cat, name, this));
                }
                return categories;
            }
        }

        internal NtResult<List<S>> GetSubCategories(Func<Guid, string, AuditCategory<T, S>, S> create_sub_category, bool throw_on_error)
        {
            return SecurityNativeMethods.AuditEnumerateSubCategories(Id, false,
                out SafeAuditBuffer buffer, out uint count)
                .CreateWin32Result(throw_on_error, () => GetSubCategories(buffer, count, create_sub_category));
        }
    }
}
