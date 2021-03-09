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

using NtApiDotNet.Utilities.SafeBuffers;
using NtApiDotNet.Win32.DirectoryService;
using NtApiDotNet.Win32.SafeHandles;
using NtApiDotNet.Win32.Security.Authorization;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace NtApiDotNet.Win32.Security
{
#pragma warning restore 1591

    /// <summary>
    /// Security utilities which call the Win32 APIs.
    /// </summary>
    public static class Win32Security
    {
        #region Internal Members
        internal static SecureString ToSecureString(this string str)
        {
            if (str == null)
                return null;
            SecureString ret = new SecureString();
            foreach (char ch in str)
            {
                ret.AppendChar(ch);
            }
            return ret;
        }

        #endregion

        #region Static Methods
        /// <summary>
        /// Set security using a named object.
        /// </summary>
        /// <param name="name">The name of the object.</param>
        /// <param name="type">The type of named object.</param>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus SetSecurityInfo(string name, SeObjectType type, 
            SecurityInformation security_information, 
            SecurityDescriptor security_descriptor, bool throw_on_error)
        {
            return SecurityNativeMethods.SetNamedSecurityInfo(
                name, type, security_information, 
                security_descriptor.Owner?.Sid.ToArray(),
                security_descriptor.Group?.Sid.ToArray(), 
                security_descriptor.Dacl?.ToByteArray(),
                security_descriptor.Sacl?.ToByteArray()).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Set security using a named object.
        /// </summary>
        /// <param name="name">The name of the object.</param>
        /// <param name="type">The type of named object.</param>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="invoke_setting">Specify to indicate when to execute progress function.</param>
        /// <param name="action">The security operation to perform on the tree.</param>
        /// <param name="progress_function">Progress function.</param>
        public static void SetSecurityInfo(string name, SeObjectType type,
            SecurityInformation security_information,
            SecurityDescriptor security_descriptor,
            TreeSecInfo action,
            TreeProgressFunction progress_function,
            ProgressInvokeSetting invoke_setting
            )
        {
            SetSecurityInfo(name, type, security_information, security_descriptor, action, progress_function, invoke_setting, true);
        }

        /// <summary>
        /// Set security using a named object.
        /// </summary>
        /// <param name="name">The name of the object.</param>
        /// <param name="type">The type of named object.</param>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="invoke_setting">Specify to indicate when to execute progress function.</param>
        /// <param name="action">The security operation to perform on the tree.</param>
        /// <param name="progress_function">Progress function.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus SetSecurityInfo(string name, SeObjectType type,
            SecurityInformation security_information,
            SecurityDescriptor security_descriptor,
            TreeSecInfo action,
            TreeProgressFunction progress_function,
            ProgressInvokeSetting invoke_setting,
            bool throw_on_error)
        {
            return SecurityNativeMethods.TreeSetNamedSecurityInfo(
                name, type, security_information,
                security_descriptor.Owner?.Sid.ToArray(),
                security_descriptor.Group?.Sid.ToArray(),
                security_descriptor.Dacl?.ToByteArray(),
                security_descriptor.Sacl?.ToByteArray(),
                action,
                CreateCallback(progress_function),
                invoke_setting,
                IntPtr.Zero
                ).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Set security using a named object.
        /// </summary>
        /// <param name="name">The name of the object.</param>
        /// <param name="type">The type of named object.</param>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <returns>The Win32 Error Code.</returns>
        public static void SetSecurityInfo(string name, SeObjectType type,
            SecurityInformation security_information,
            SecurityDescriptor security_descriptor)
        {
            SetSecurityInfo(name, type, security_information, security_descriptor, true);
        }

        /// <summary>
        /// Set security using an object handle.
        /// </summary>
        /// <param name="handle">The handle of the object.</param>
        /// <param name="type">The type of object.</param>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus SetSecurityInfo(SafeHandle handle, SeObjectType type,
            SecurityInformation security_information,
            SecurityDescriptor security_descriptor, bool throw_on_error)
        {
            return SecurityNativeMethods.SetSecurityInfo(
                handle, type, security_information,
                security_descriptor.Owner?.Sid.ToArray(),
                security_descriptor.Group?.Sid.ToArray(),
                security_descriptor.Dacl?.ToByteArray(),
                security_descriptor.Sacl?.ToByteArray())
                .ToNtException(throw_on_error);
        }

        /// <summary>
        /// Set security using an object handle.
        /// </summary>
        /// <param name="handle">The handle of the object.</param>
        /// <param name="type">The type of object.</param>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        public static void SetSecurityInfo(SafeHandle handle, SeObjectType type,
            SecurityInformation security_information,
            SecurityDescriptor security_descriptor)
        {
            SetSecurityInfo(handle, type, security_information, security_descriptor, true);
        }

        /// <summary>
        /// Set security using an object handle.
        /// </summary>
        /// <param name="obj">The handle of the object.</param>
        /// <param name="type">The type of object.</param>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus SetSecurityInfo(NtObject obj, SeObjectType type,
            SecurityInformation security_information,
            SecurityDescriptor security_descriptor, bool throw_on_error)
        {
            return SetSecurityInfo(obj.Handle, type, security_information, security_descriptor, throw_on_error);
        }

        /// <summary>
        /// Set security using an object handle.
        /// </summary>
        /// <param name="obj">The handle of the object.</param>
        /// <param name="type">The type of object.</param>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        public static void SetSecurityInfo(NtObject obj, SeObjectType type,
            SecurityInformation security_information,
            SecurityDescriptor security_descriptor)
        {
            SetSecurityInfo(obj, type, security_information, security_descriptor, true);
        }

        /// <summary>
        /// Reset security using a named object.
        /// </summary>
        /// <param name="name">The name of the object.</param>
        /// <param name="type">The type of named object.</param>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="keep_explicit">True to keep explicit ACEs.</param>
        /// <param name="invoke_setting">Specify to indicate when to execute progress function.</param>

        /// <param name="progress_function">Progress function.</param>
        public static void ResetSecurityInfo(string name, SeObjectType type,
            SecurityInformation security_information,
            SecurityDescriptor security_descriptor,
            TreeProgressFunction progress_function,
            ProgressInvokeSetting invoke_setting,
            bool keep_explicit
            )
        {
            ResetSecurityInfo(name, type, security_information, security_descriptor, 
                progress_function, invoke_setting, keep_explicit, true);
        }

        /// <summary>
        /// Reset security using a named object.
        /// </summary>
        /// <param name="name">The name of the object.</param>
        /// <param name="type">The type of named object.</param>
        /// <param name="security_information">The security information to set.</param>
        /// <param name="security_descriptor">The security descriptor to set.</param>
        /// <param name="invoke_setting">Specify to indicate when to execute progress function.</param>
        /// <param name="keep_explicit">True to keep explicit ACEs.</param>
        /// <param name="progress_function">Progress function.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus ResetSecurityInfo(string name, SeObjectType type,
            SecurityInformation security_information,
            SecurityDescriptor security_descriptor,
            TreeProgressFunction progress_function,
            ProgressInvokeSetting invoke_setting,
            bool keep_explicit,
            bool throw_on_error)
        {
            return SecurityNativeMethods.TreeResetNamedSecurityInfo(
                name, type, security_information,
                security_descriptor.Owner?.Sid.ToArray(),
                security_descriptor.Group?.Sid.ToArray(),
                security_descriptor.Dacl?.ToByteArray(),
                security_descriptor.Sacl?.ToByteArray(),
                keep_explicit,
                CreateCallback(progress_function),
                invoke_setting,
                IntPtr.Zero
                ).ToNtException(throw_on_error);
        }

        /// <summary>
        /// Get the source of inherited ACEs.
        /// </summary>
        /// <param name="name">The name of the resource.</param>
        /// <param name="type">The type of the resource.</param>
        /// <param name="container">Whether the resource is a container.</param>
        /// <param name="object_types">Optional list of object types.</param>
        /// <param name="security_descriptor">The security descriptor for the resource.</param>
        /// <param name="sacl">True to check the SACL otherwise checks the DACL.</param>
        /// <param name="generic_mapping">Generic mapping for the resource.</param>
        /// <param name="query_security">Query security descriptors for sources.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of inheritance sources.</returns>
        public static NtResult<IEnumerable<SecurityDescriptorInheritanceSource>> GetInheritanceSource(
            string name,
            SeObjectType type,
            bool container,
            Guid[] object_types,
            SecurityDescriptor security_descriptor,
            bool sacl,
            GenericMapping generic_mapping,
            bool query_security,
            bool throw_on_error)
        {
            Acl acl = sacl ? security_descriptor.Sacl : security_descriptor.Dacl;
            if (acl == null || acl.NullAcl)
            {
                return NtStatus.STATUS_INVALID_ACL.CreateResultFromError<IEnumerable<SecurityDescriptorInheritanceSource>>(throw_on_error);
            }

            using (var list = new DisposableList())
            {
                SafeGuidArrayBuffer guids = SafeGuidArrayBuffer.Null;
                if (object_types?.Length > 0)
                {
                    guids = list.AddResource(new SafeGuidArrayBuffer(object_types));
                }

                NtType native_type = GetNativeType(type);

                INHERITED_FROM[] inherited_from = new INHERITED_FROM[acl.Count];
                NtStatus status = NtStatus.STATUS_INVALID_PARAMETER;
                try
                {
                    status = SecurityNativeMethods.GetInheritanceSource(name, type, sacl ? SecurityInformation.Sacl : SecurityInformation.Dacl,
                        container, guids, guids.Count, acl.ToByteArray(), IntPtr.Zero, ref generic_mapping, inherited_from).MapDosErrorToStatus();
                    return status.CreateResult(throw_on_error, () => (IEnumerable<SecurityDescriptorInheritanceSource>)inherited_from
                        .Select((s, i) => new SecurityDescriptorInheritanceSource(acl[i], s, type,
                        native_type, container, query_security, sacl)).Where(s => s.Depth != -1).ToArray());
                }
                finally
                {
                    if (status.IsSuccess())
                    {
                        SecurityNativeMethods.FreeInheritedFromArray(inherited_from, (ushort)inherited_from.Length, IntPtr.Zero);
                    }
                }
            }
        }

        /// <summary>
        /// Get the source of inherited ACEs.
        /// </summary>
        /// <param name="name">The name of the resource.</param>
        /// <param name="type">The type of the resource.</param>
        /// <param name="container">Whether the resource is a container.</param>
        /// <param name="object_types">Optional list of object types.</param>
        /// <param name="security_descriptor">The security descriptor for the resource.</param>
        /// <param name="sacl">True to check the SACL otherwise checks the DACL.</param>
        /// <param name="generic_mapping">Generic mapping for the resource.</param>
        /// <param name="query_security">Query security descriptors for sources.</param>
        /// <returns>The list of inheritance sources.</returns>
        public static IEnumerable<SecurityDescriptorInheritanceSource> GetInheritanceSource(
            string name,
            SeObjectType type,
            bool container,
            Guid[] object_types,
            SecurityDescriptor security_descriptor,
            bool sacl,
            GenericMapping generic_mapping,
            bool query_security)
        {
            return GetInheritanceSource(name, type, container, object_types, 
                security_descriptor, sacl, generic_mapping, 
                query_security, true).Result;
        }

        /// <summary>
        /// Get the security descriptor for a named resource.
        /// </summary>
        /// <param name="name">The name of the resource.</param>
        /// <param name="type">The type of the resource.</param>
        /// <param name="security_information">The security information to get.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The security descriptor.</returns>
        public static NtResult<SecurityDescriptor> GetSecurityInfo(
            string name,
            SeObjectType type,
            SecurityInformation security_information,
            bool throw_on_error)
        {
            using (var result = SecurityNativeMethods.GetNamedSecurityInfo(name, type,
                security_information, null,
                null, null, null, out SafeLocalAllocBuffer sd).MapDosErrorToStatus().CreateResult(throw_on_error, () => sd))
            {
                if (!result.IsSuccess)
                {
                    return result.Cast<SecurityDescriptor>();
                }

                if (result.Result.IsInvalid)
                {
                    return NtStatus.STATUS_INVALID_SECURITY_DESCR.CreateResultFromError<SecurityDescriptor>(throw_on_error);
                }

                return SecurityDescriptor.Parse(result.Result, GetNativeType(type), throw_on_error);
            }
        }

        /// <summary>
        /// Get the security descriptor for a named resource.
        /// </summary>
        /// <param name="name">The name of the resource.</param>
        /// <param name="type">The type of the resource.</param>
        /// <param name="security_information">The security information to get.</param>
        /// <returns>The security descriptor.</returns>
        public static SecurityDescriptor GetSecurityInfo(
            string name,
            SeObjectType type,
            SecurityInformation security_information)
        {
            return GetSecurityInfo(name, type, security_information, true).Result;
        }

        /// <summary>
        /// Get the security descriptor for a resource.
        /// </summary>
        /// <param name="handle">The handle to the resource.</param>
        /// <param name="type">The type of the resource.</param>
        /// <param name="security_information">The security information to get.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The security descriptor.</returns>
        public static NtResult<SecurityDescriptor> GetSecurityInfo(
            SafeHandle handle,
            SeObjectType type,
            SecurityInformation security_information,
            bool throw_on_error)
        {
            using (var result = SecurityNativeMethods.GetSecurityInfo(handle, type,
                security_information, null,
                null, null, null, out SafeLocalAllocBuffer sd).MapDosErrorToStatus().CreateResult(throw_on_error, () => sd))
            {
                if (!result.IsSuccess)
                {
                    return result.Cast<SecurityDescriptor>();
                }

                NtType sd_type = null;
                if (handle is SafeKernelObjectHandle kernel_handle)
                {
                    sd_type = NtType.GetTypeByName(kernel_handle.NtTypeName, false);
                }

                return SecurityDescriptor.Parse(result.Result, sd_type ?? GetNativeType(type), throw_on_error);
            }
        }

        /// <summary>
        /// Get the security descriptor for a resource.
        /// </summary>
        /// <param name="handle">The handle to the resource.</param>
        /// <param name="type">The type of the resource.</param>
        /// <param name="security_information">The security information to get.</param>
        /// <returns>The security descriptor.</returns>
        public static SecurityDescriptor GetSecurityInfo(
            SafeHandle handle,
            SeObjectType type,
            SecurityInformation security_information)
        {
            return GetSecurityInfo(handle, type, security_information, true).Result;
        }

        /// <summary>
        /// Get the NT type for a SE Object Type.
        /// </summary>
        /// <param name="type">The type of the resource.</param>
        /// <returns>The NT type if known, otherwise null.</returns>
        public static NtType GetNativeType(SeObjectType type)
        {
            switch (type)
            {
                case SeObjectType.File:
                case SeObjectType.LMShare:
                    return NtType.GetTypeByType<NtFile>();
                case SeObjectType.RegistryKey:
                case SeObjectType.RegistryWow6432Key:
                case SeObjectType.RegistryWow6464Key:
                    return NtType.GetTypeByType<NtKey>();
                case SeObjectType.Service:
                    return NtType.GetTypeByName(ServiceUtils.SERVICE_NT_TYPE_NAME);
                case SeObjectType.WmiGuid:
                    return NtType.GetTypeByType<NtEtwRegistration>();
                case SeObjectType.Ds:
                case SeObjectType.DsAll:
                    return NtType.GetTypeByName(DirectoryServiceUtils.DS_NT_TYPE_NAME);
            }
            return null;
        }

        /// <summary>
        /// Lookup a privilege display name.
        /// </summary>
        /// <param name="system_name">The system name to do the lookup on.</param>
        /// <param name="privilege_name">The privilege name.</param>
        /// <returns>The display name. Empty string on error.</returns>
        public static string LookupPrivilegeDisplayName(string system_name, string privilege_name)
        {
            int name_length = 0;
            Win32NativeMethods.LookupPrivilegeDisplayName(system_name, privilege_name, null, ref name_length, out int lang_id);
            if (name_length <= 0)
            {
                return  string.Empty;
            }

            StringBuilder builder = new StringBuilder(name_length + 1);
            name_length = builder.Capacity;
            if (Win32NativeMethods.LookupPrivilegeDisplayName(system_name, privilege_name, builder, ref name_length, out lang_id))
            {
                return builder.ToString();
            }
            return string.Empty;
        }

        /// <summary>
        /// Add a SID to name mapping with LSA.
        /// </summary>
        /// <param name="domain">The domain name for the SID. The SID must be in the NT authority.</param>
        /// <param name="name">The account name for the SID. Can be null for a domain SID.</param>
        /// <param name="sid">The SID to add.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status result.</returns>
        public static NtStatus AddSidNameMapping(string domain, string name, Sid sid, bool throw_on_error)
        {
            using (var sid_buffer = sid.ToSafeBuffer())
            {
                LSA_SID_NAME_MAPPING_OPERATION_ADD_INPUT input = new LSA_SID_NAME_MAPPING_OPERATION_ADD_INPUT
                {
                    Sid = sid_buffer.DangerousGetHandle(),
                    DomainName = new UnicodeStringIn(domain)
                };
                if (!string.IsNullOrEmpty(name))
                {
                    input.AccountName = new UnicodeStringIn(name);
                }
                
                using (var input_buffer = input.ToBuffer())
                {
                    SafeLsaMemoryBuffer output = null;
                    try
                    {
                        return SecurityNativeMethods.LsaManageSidNameMapping(LSA_SID_NAME_MAPPING_OPERATION_TYPE.LsaSidNameMappingOperation_Add,
                            input_buffer, out output).ToNtException(throw_on_error);
                    }
                    finally
                    {
                        output?.Dispose();
                    }
                }
            }
        }

        /// <summary>
        /// Add a SID to name mapping with LSA.
        /// </summary>
        /// <param name="domain">The domain name for the SID.</param>
        /// <param name="name">The account name for the SID. Can be null for a domain SID.</param>
        /// <param name="sid">The SID to add.</param>
        /// <returns>The NT status result.</returns>
        public static void AddSidNameMapping(string domain, string name, Sid sid)
        {
            AddSidNameMapping(domain, name, sid, true);
        }

        /// <summary>
        /// Remove a SID to name mapping with LSA.
        /// </summary>
        /// <param name="domain">The domain name for the SID.</param>
        /// <param name="name">The account name for the SID. Can be null for a domain SID.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status result.</returns>
        public static NtStatus RemoveSidNameMapping(string domain, string name, bool throw_on_error)
        {
            LSA_SID_NAME_MAPPING_OPERATION_REMOVE_INPUT input = new LSA_SID_NAME_MAPPING_OPERATION_REMOVE_INPUT
            {
                DomainName = new UnicodeStringIn(domain)
            };
            if (name != null)
            {
                input.AccountName = new UnicodeStringIn(name);
            }

            using (var input_buffer = input.ToBuffer())
            {
                SafeLsaMemoryBuffer output = null;
                try
                {
                    return SecurityNativeMethods.LsaManageSidNameMapping(LSA_SID_NAME_MAPPING_OPERATION_TYPE.LsaSidNameMappingOperation_Remove,
                        input_buffer, out output).ToNtException(throw_on_error);
                }
                finally
                {
                    output?.Dispose();
                }
            }
        }

        /// <summary>
        /// Remove a SID to name mapping with LSA.
        /// </summary>
        /// <param name="domain">The domain name for the SID.</param>
        /// <param name="name">The account name for the SID. Can be null for a domain SID.</param>
        /// <returns>The NT status result.</returns>
        public static void RemoveSidNameMapping(string domain, string name)
        {
            RemoveSidNameMapping(domain, name, true);
        }

        /// <summary>
        /// Remove a SID to name mapping with LSA.
        /// </summary>
        /// <param name="sid">The SID to remove.</param>
        /// <returns>The NT status result.</returns>
        public static void RemoveSidNameMapping(Sid sid)
        {
            SidName name = sid.GetName();
            RemoveSidNameMapping(name.Domain, name.NameUse == SidNameUse.Domain ? string.Empty : name.Name, true);
        }

        /// <summary>
        /// Logon a user with a username and password.
        /// </summary>
        /// <param name="user">The username.</param>
        /// <param name="domain">The user's domain.</param>
        /// <param name="password">The user's password.</param>
        /// <param name="type">The type of logon token.</param>
        /// <param name="provider">The Logon provider.</param>
        /// <returns>The logged on token.</returns>
        public static NtToken LsaLogonUser(string user, string domain, SecureString password, SecurityLogonType type, Logon32Provider provider)
        {
            return LsaLogonUser(user, domain, password, type, provider, true).Result;
        }

        /// <summary>
        /// Logon a user with a username and password.
        /// </summary>
        /// <param name="user">The username.</param>
        /// <param name="domain">The user's domain.</param>
        /// <param name="password">The user's password.</param>
        /// <param name="type">The type of logon token.</param>
        /// <param name="provider">The Logon provider.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The logged on token.</returns>
        public static NtResult<NtToken> LsaLogonUser(string user, string domain, SecureString password, SecurityLogonType type, Logon32Provider provider, bool throw_on_error)
        {
            using (var pwd = new SecureStringMarshalBuffer(password))
            {
                return SecurityNativeMethods.LogonUser(user, domain, pwd, type, provider,
                    out SafeKernelObjectHandle handle).CreateWin32Result(throw_on_error, () => new NtToken(handle));
            }
        }

        /// <summary>
        /// Logon a user with a username and password.
        /// </summary>
        /// <param name="user">The username.</param>
        /// <param name="domain">The user's domain.</param>
        /// <param name="password">The user's password.</param>
        /// <param name="type">The type of logon token.</param>
        /// <param name="provider">The Logon provider.</param>
        /// <param name="groups">Additional groups to add. Needs SeTcbPrivilege.</param>
        /// <returns>The logged on token.</returns>
        public static NtToken LsaLogonUser(string user, string domain, SecureString password, SecurityLogonType type, Logon32Provider provider, IEnumerable<UserGroup> groups)
        {
            return LsaLogonUser(user, domain, password, type, provider, groups, true).Result;
        }

        /// <summary>
        /// Logon a user with a username and password.
        /// </summary>
        /// <param name="user">The username.</param>
        /// <param name="domain">The user's domain.</param>
        /// <param name="password">The user's password.</param>
        /// <param name="type">The type of logon token.</param>
        /// <param name="provider">The Logon provider.</param>
        /// <param name="groups">Additional groups to add. Needs SeTcbPrivilege.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The logged on token.</returns>
        public static NtResult<NtToken> LsaLogonUser(string user, string domain, SecureString password, SecurityLogonType type, Logon32Provider provider,
            IEnumerable<UserGroup> groups, bool throw_on_error)
        {
            if (groups is null)
            {
                return LsaLogonUser(user, domain, password, type, provider, throw_on_error);
            }

            TokenGroupsBuilder builder = new TokenGroupsBuilder();
            foreach (var group in groups)
            {
                builder.AddGroup(group.Sid, group.Attributes);
            }

            using (var group_buffer = builder.ToBuffer())
            {
                using (var pwd = new SecureStringMarshalBuffer(password))
                {
                    return SecurityNativeMethods.LogonUserExExW(user, domain, pwd, type, provider, group_buffer,
                        out SafeKernelObjectHandle token, null, null, null, null)
                        .CreateWin32Result(throw_on_error, () => new NtToken(token));
                }
            }
        }

        /// <summary>
        /// Lookup a SID's internet name.
        /// </summary>
        /// <param name="sid">The SID to lookup.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The name of the sid as an internet account.</returns>
        /// <remarks>This still might return the normal NT4 style account name if the user is not an internet user.</remarks>
        [SupportedVersion(SupportedVersion.Windows8)]
        public static NtResult<SidName> LookupInternetName(Sid sid, bool throw_on_error)
        {
            if (NtObjectUtils.IsWindows7OrLess)
                throw new NotSupportedException($"{nameof(LookupInternetName)} isn't supported until Windows 8");

            return LookupSids2(null, new Sid[] { sid }, LsaLookupOptions.LSA_LOOKUP_PREFER_INTERNET_NAMES, throw_on_error).Map(e => e.First());
        }

        /// <summary>
        /// Lookup a SID's internet name.
        /// </summary>
        /// <param name="sid">The SID to lookup.</param>
        /// <returns>The name of the sid as an internet account.</returns>
        /// <remarks>This still might return the normal NT4 style account name if the user is not an internet user.</remarks>
        [SupportedVersion(SupportedVersion.Windows8)]
        public static SidName LookupInternetName(Sid sid)
        {
            return LookupInternetName(sid, true).Result;
        }

        #endregion

        #region Private Members
        private static TreeSetNamedSecurityProgress CreateCallback(TreeProgressFunction progress_function)
        {
            if (progress_function != null)
            {
                return (string n, Win32Error s,
                    ref ProgressInvokeSetting p, IntPtr a, bool t)
                        => p = progress_function(n, s, p, t);
            }
            return null;
        }

        private static IEnumerable<SidName> GetSidNames(Sid[] sids, SafeLsaMemoryBuffer domains, SafeLsaMemoryBuffer names)
        {
            List<SidName> ret = new List<SidName>();
            domains.Initialize<LSA_REFERENCED_DOMAIN_LIST>(1);
            names.Initialize<LSA_TRANSLATED_NAME>((uint)sids.Length);

            var domain_list = domains.Read<LSA_REFERENCED_DOMAIN_LIST>(0);
            var domains_entries = NtProcess.Current.ReadMemoryArray<LSA_TRUST_INFORMATION>(domain_list.Domains.ToInt64(), domain_list.Entries);
            var name_list = names.ReadArray<LSA_TRANSLATED_NAME>(0, sids.Length);

            for (int i = 0; i < sids.Length; ++i)
            {
                var name = name_list[i];

                ret.Add(new SidName(sids[i], name.GetDomain(domains_entries),
                    name.GetName(), SidNameSource.Account, name.Use, false));
            }
            return ret.AsReadOnly();
        }

        private static NtResult<IEnumerable<SidName>> LookupSids2(string system_name, Sid[] sids, LsaLookupOptions options, bool throw_on_error)
        {
            using (var policy = SafeLsaHandle.OpenPolicy(system_name, Policy.LsaPolicyAccessRights.LookupNames, throw_on_error))
            {
                if (!policy.IsSuccess)
                {
                    return policy.Cast<IEnumerable<SidName>>();
                }

                using (var list = new DisposableList())
                {
                    var sid_ptrs = sids.Select(s => list.AddSid(s).DangerousGetHandle()).ToArray();
                    var status = SecurityNativeMethods.LsaLookupSids2(policy.Result, options, sid_ptrs.Length, sid_ptrs, 
                        out SafeLsaMemoryBuffer domains, out SafeLsaMemoryBuffer names);
                    if (!status.IsSuccess())
                    {
                        if (status == NtStatus.STATUS_NONE_MAPPED)
                        {
                            list.Add(domains);
                            list.Add(names);
                        }
                        return status.CreateResultFromError<IEnumerable<SidName>>(throw_on_error);
                    }

                    return GetSidNames(sids, domains, names).CreateResult();
                }
            }
        }

        #endregion
    }
}
