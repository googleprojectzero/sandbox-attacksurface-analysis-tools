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
using System.Text;

namespace NtApiDotNet.Win32.Security
{
#pragma warning restore 1591

    /// <summary>
    /// Security utilities which call the Win32 APIs.
    /// </summary>
    public static class Win32Security
    {
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
                    return NtType.GetTypeByType<NtFile>();
                case SeObjectType.RegistryKey:
                case SeObjectType.RegistryWow6432Key:
                case SeObjectType.RegistryWow6464Key:
                    return NtType.GetTypeByType<NtKey>();
                case SeObjectType.Service:
                    return ServiceUtils.GetServiceNtType("Service");
                case SeObjectType.WmiGuid:
                    return NtType.GetTypeByType<NtEtwRegistration>();
                case SeObjectType.Ds:
                case SeObjectType.DsAll:
                    return DirectoryServiceUtils.NtType;
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

        #endregion
    }
}
