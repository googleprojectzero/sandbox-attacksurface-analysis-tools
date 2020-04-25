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
    /// Utilities for security auditing policy.
    /// </summary>
    public static class AuditSecurityUtils
    {
        /// <summary>
        /// Get the generic mapping for directory services.
        /// </summary>
        /// <returns>The directory services generic mapping.</returns>
        public static GenericMapping GenericMapping
        {
            get
            {
                GenericMapping mapping = new GenericMapping
                {
                    GenericRead = AuditAccessRights.QuerySystemPolicy | AuditAccessRights.QueryUserPolicy 
                    | AuditAccessRights.EnumerateUsers | AuditAccessRights.QueryMiscPolicy | AuditAccessRights.ReadControl,
                    GenericWrite = AuditAccessRights.SetUserPolicy | AuditAccessRights.SetMiscPolicy | AuditAccessRights.SetSystemPolicy | AuditAccessRights.ReadControl,
                    GenericExecute = AuditAccessRights.ReadControl,
                    GenericAll = AuditAccessRights.All
                };
                return mapping;
            }
        }

        /// <summary>
        /// Get a fake NtType for System Audit Policy.
        /// </summary>
        /// <returns>The fake Directory Services NtType</returns>
        public static NtType NtType => new NtType("Audit", GenericMapping,
                        typeof(AuditAccessRights), typeof(AuditAccessRights),
                        MandatoryLabelPolicy.NoWriteUp);

        /// <summary>
        /// Query the Auditing Security Descriptor.
        /// </summary>
        /// <param name="security_information">The security information to query.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The security descriptor.</returns>
        public static NtResult<SecurityDescriptor> QuerySecurity(SecurityInformation security_information, bool throw_on_error)
        {
            if (!SecurityNativeMethods.AuditQuerySecurity(security_information, out SafeAuditBuffer buffer))
                return NtObjectUtils.MapDosErrorToStatus().CreateResultFromError<SecurityDescriptor>(throw_on_error);
            using (buffer)
            {
                return SecurityDescriptor.Parse(buffer, NtType, throw_on_error);
            }
        }

        /// <summary>
        /// Query the Auditing Security Descriptor.
        /// </summary>
        /// <param name="security_information">The security information to query.</param>
        /// <returns>The security descriptor.</returns>
        public static SecurityDescriptor QuerySecurity(SecurityInformation security_information)
        {
            return QuerySecurity(security_information, true).Result;
        }

        /// <summary>
        /// Query the Auditing Security Descriptor.
        /// </summary>
        /// <returns>The security descriptor.</returns>
        public static SecurityDescriptor QuerySecurity()
        {
            return QuerySecurity(SecurityInformation.Dacl | SecurityInformation.Sacl);
        }

        /// <summary>
        /// Set the Auditing Security Descriptor.
        /// </summary>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus SetSecurity(SecurityInformation security_information, SecurityDescriptor security_descriptor, bool throw_on_error)
        {
            using (var buffer = security_descriptor.ToSafeBuffer())
            {
                if (!SecurityNativeMethods.AuditSetSecurity(security_information, buffer))
                {
                    return NtObjectUtils.MapDosErrorToStatus().ToNtException(throw_on_error);
                }
                return NtStatus.STATUS_SUCCESS;
            }
        }

        /// <summary>
        /// Set the Auditing Security Descriptor.
        /// </summary>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <returns>The NT status code.</returns>
        public static void SetSecurity(SecurityInformation security_information, SecurityDescriptor security_descriptor)
        {
            SetSecurity(security_information, security_descriptor, true);
        }

        /// <summary>
        /// Query the global SACL.
        /// </summary>
        /// <param name="type">The global SACL type.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The global SACL in a Security Descriptor.</returns>
        public static NtResult<SecurityDescriptor> QueryGlobalSacl(AuditGlobalSaclType type, bool throw_on_error)
        {
            if (!SecurityNativeMethods.AuditQueryGlobalSacl(type.ToString(), out SafeAuditBuffer buffer))
                return NtObjectUtils.MapDosErrorToStatus().CreateResultFromError<SecurityDescriptor>(throw_on_error);
            using (buffer)
            {
                NtType nt_type = type == AuditGlobalSaclType.File ? NtType.GetTypeByType<NtFile>() : NtType.GetTypeByType<NtKey>();
                return new SecurityDescriptor(nt_type) { Sacl = new Acl(buffer.DangerousGetHandle(), false) }.CreateResult();
            }
        }

        /// <summary>
        /// Query the global SACL.
        /// </summary>
        /// <param name="type">The global SACL type.</param>
        /// <returns>The global SACL in a Security Descriptor.</returns>
        public static SecurityDescriptor QueryGlobalSacl(AuditGlobalSaclType type)
        {
            return QueryGlobalSacl(type, true).Result;
        }

        /// <summary>
        /// Set the global SACL.
        /// </summary>
        /// <param name="type">The global SACL type.</param>
        /// <param name="security_descriptor">The SACL to set in an Security Descriptor.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus SetGlobalSacl(AuditGlobalSaclType type, SecurityDescriptor security_descriptor, bool throw_on_error)
        {
            if (!security_descriptor.SaclPresent)
                throw new ArgumentException("Must specify a SACL.");
            using (var buffer = security_descriptor.Sacl.ToSafeBuffer())
            {
                if (!SecurityNativeMethods.AuditSetGlobalSacl(type.ToString(), buffer))
                {
                    return NtObjectUtils.MapDosErrorToStatus().ToNtException(throw_on_error);
                }
                return NtStatus.STATUS_SUCCESS;
            }
        }

        /// <summary>
        /// Set the global SACL.
        /// </summary>
        /// <param name="type">The global SACL type.</param>
        /// <param name="security_descriptor">The SACL to set in an Security Descriptor.</param>
        /// <returns>The NT status code.</returns>
        public static void SetGlobalSacl(AuditGlobalSaclType type, SecurityDescriptor security_descriptor)
        {
            SetGlobalSacl(type, security_descriptor, true);
        }

        /// <summary>
        /// Get list of Audit Policy categories.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of categories.</returns>
        public static NtResult<IReadOnlyList<AuditCategory>> GetCategories(bool throw_on_error)
        {
            return GetCategoriesInternal(throw_on_error).Map(a => a.ToList().AsReadOnly()).Cast<IReadOnlyList<AuditCategory>>();
        }

        /// <summary>
        /// Get list of Audit Policy categories.
        /// </summary>
        /// <returns>The list of categories.</returns>
        public static IReadOnlyList<AuditCategory> GetCategories()
        {
            return GetCategories(true).Result;
        }

        /// <summary>
        /// Get a single category.
        /// </summary>
        /// <param name="type">The category type.</param>
        /// <returns>The audit category.</returns>
        public static AuditCategory GetCategory(AuditPolicyEventType type)
        {
            return GetCategoryInternal(type, true).Result;
        }

        /// <summary>
        /// Get a single category.
        /// </summary>
        /// <param name="category">The category GUID.</param>
        /// <returns>The audit category.</returns>
        public static AuditCategory GetCategory(Guid category)
        {
            return GetCategoryInternal(category, true).Result;
        }

        /// <summary>
        /// Get all per-user categories for denied users.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of per-user categories.</returns>
        public static NtResult<IReadOnlyList<AuditPerUserCategory>> GetPerUserCategories(bool throw_on_error)
        {
            var sids = GetValidUsers(throw_on_error);
            if (!sids.IsSuccess)
                return sids.Cast<IReadOnlyList<AuditPerUserCategory>>();
            List<AuditPerUserCategory> ret = new List<AuditPerUserCategory>();
            foreach (var sid in sids.Result)
            {
                var cats = GetPerUserCategories(sid, throw_on_error);
                if (!cats.IsSuccess)
                    return cats.Cast<IReadOnlyList<AuditPerUserCategory>>();
                ret.AddRange(cats.Result);
            }
            return ret.AsReadOnly().CreateResult<IReadOnlyList<AuditPerUserCategory>>();
        }

        /// <summary>
        /// Get all per-user categories for denied users.
        /// </summary>
        /// <returns>The list of per-user categories.</returns>
        public static IReadOnlyList<AuditPerUserCategory> GetPerUserCategories()
        {
            return GetPerUserCategories(true).Result;
        }

        /// <summary>
        /// Get list of per-user Audit Policy categories.
        /// </summary>
        /// <param name="user">The user SID to query.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of categories.</returns>
        public static NtResult<IReadOnlyList<AuditPerUserCategory>> GetPerUserCategories(Sid user, bool throw_on_error)
        {
            return GetPerUserCategoriesInternal(user, throw_on_error)
                .Map(a => a.ToList().AsReadOnly()).Cast<IReadOnlyList<AuditPerUserCategory>>();
        }

        /// <summary>
        /// Get list of per-user Audit Policy categories.
        /// </summary>
        /// <param name="user">The user SID to query.</param>
        /// <returns>The list of categories.</returns>
        public static IReadOnlyList<AuditPerUserCategory> GetPerUserCategories(Sid user)
        {
            return GetPerUserCategories(user, true).Result;
        }

        /// <summary>
        /// Get a single per-user category.
        /// </summary>
        /// <param name="user">The user SID to query.</param>
        /// <param name="type">The category type.</param>
        /// <returns>The audit category.</returns>
        public static AuditPerUserCategory GetPerUserCategory(Sid user, AuditPolicyEventType type)
        {
            return GetPerUserCategoryInternal(user, type, true).Result;
        }

        /// <summary>
        /// Get a single per-user category.
        /// </summary>
        /// <param name="user">The user SID to query.</param>
        /// <param name="category">The category GUID.</param>
        /// <returns>The audit category.</returns>
        public static AuditPerUserCategory GetPerUserCategory(Sid user, Guid category)
        {
            return GetPerUserCategoryInternal(user, category, true).Result;
        }

        #region Private Members
        private static NtResult<string> LookupCategoryName(Guid category, bool throw_on_error)
        {
            return SecurityNativeMethods.AuditLookupCategoryName(ref category,
                out SafeAuditBuffer buffer).CreateWin32Result(throw_on_error, () => {
                    using (buffer)
                    {
                        return Marshal.PtrToStringUni(buffer.DangerousGetHandle());
                    }
                });
        }

        private static Z[] GetCategories<Z>(SafeAuditBuffer buffer, uint count, Func<Guid, string, Z> create)
        {
            using (buffer)
            {
                List<Z> categories = new List<Z>();
                buffer.Initialize<Guid>(count);
                Guid[] cats = new Guid[count];
                buffer.ReadArray(0, cats, 0, (int)count);

                foreach (Guid cat in cats)
                {
                    var name = LookupCategoryName(cat, false).GetResultOrDefault(cat.ToString());
                    categories.Add(create(cat, name));
                }
                return categories.ToArray();
            }
        }

        private static NtResult<AuditCategory[]> GetCategoriesInternal(bool throw_on_error)
        {
            return SecurityNativeMethods.AuditEnumerateCategories(out SafeAuditBuffer buffer,
                out uint count).CreateWin32Result(throw_on_error, ()
                => GetCategories(buffer, count, (i, n) => new AuditCategory(i, n)));
        }

        private static NtResult<AuditCategory> GetCategoryInternal(Guid category, bool throw_on_error)
        {
            return LookupCategoryName(category, throw_on_error).Map(s => new AuditCategory(category, s));
        }

        private static NtResult<AuditCategory> GetCategoryInternal(AuditPolicyEventType type, bool throw_on_error)
        {
            if (!SecurityNativeMethods.AuditLookupCategoryGuidFromCategoryId(type, out Guid category))
                return NtObjectUtils.MapDosErrorToStatus().CreateResultFromError<AuditCategory>(throw_on_error);
            return GetCategoryInternal(category, throw_on_error);
        }

        private static NtResult<AuditPerUserCategory[]> GetPerUserCategoriesInternal(Sid user, bool throw_on_error)
        {
            return SecurityNativeMethods.AuditEnumerateCategories(out SafeAuditBuffer buffer,
                out uint count).CreateWin32Result(throw_on_error, () => GetCategories(buffer, count,
                (i, n) => new AuditPerUserCategory(i, n, user)));
        }

        private static NtResult<AuditPerUserCategory> GetPerUserCategoryInternal(Sid user, Guid category, bool throw_on_error)
        {
            return LookupCategoryName(category, throw_on_error).Map(s => new AuditPerUserCategory(category, s, user));
        }

        private static NtResult<AuditPerUserCategory> GetPerUserCategoryInternal(Sid user, AuditPolicyEventType type, bool throw_on_error)
        {
            if (!SecurityNativeMethods.AuditLookupCategoryGuidFromCategoryId(type, out Guid category))
                return NtObjectUtils.MapDosErrorToStatus().CreateResultFromError<AuditPerUserCategory>(throw_on_error);
            return GetPerUserCategoryInternal(user, category, throw_on_error);
        }

        private static NtResult<List<Sid>> GetValidUsers(bool throw_on_error)
        {
            if (!SecurityNativeMethods.AuditEnumeratePerUserPolicy(out SafeAuditBuffer buffer))
            {
                return NtObjectUtils.CreateResultFromDosError<List<Sid>>(throw_on_error);
            }
            using (buffer)
            {
                List<Sid> sids = new List<Sid>();
                buffer.Initialize<POLICY_AUDIT_SID_ARRAY>(1);
                var sid_array = buffer.Read<POLICY_AUDIT_SID_ARRAY>(0);
                for (int i = 0; i < sid_array.UsersCount; ++i)
                {
                    sids.Add(new Sid(Marshal.ReadIntPtr(buffer.DangerousGetHandle(), i * IntPtr.Size)));
                }
                return sids.CreateResult();
            }
        }

        #endregion
    }
}
