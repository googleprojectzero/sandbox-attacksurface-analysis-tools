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

using NtCoreLib.Native.SafeBuffers;
using NtCoreLib.Native.SafeHandles;
using NtCoreLib.Security;
using NtCoreLib.Security.Authorization;
using NtCoreLib.Security.Token;
using NtCoreLib.Utilities.Collections;
using NtCoreLib.Utilities.Reflection;
using NtCoreLib.Utilities.Token;
using NtCoreLib.Win32.DirectoryService;
using NtCoreLib.Win32.Printing;
using NtCoreLib.Win32.SafeHandles;
using NtCoreLib.Win32.Security.Authentication;
using NtCoreLib.Win32.Security.Authentication.Kerberos;
using NtCoreLib.Win32.Security.Authentication.Logon;
using NtCoreLib.Win32.Security.Authorization;
using NtCoreLib.Win32.Security.Interop;
using NtCoreLib.Win32.Security.Policy;
using NtCoreLib.Win32.Security.Safer;
using NtCoreLib.Win32.Service;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;

namespace NtCoreLib.Win32.Security;

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

        using var list = new DisposableList();
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
        using var result = SecurityNativeMethods.GetNamedSecurityInfo(name, type,
            security_information, null,
            null, null, null, out SafeLocalAllocBuffer sd).MapDosErrorToStatus().CreateResult(throw_on_error, () => sd);
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
        using var result = SecurityNativeMethods.GetSecurityInfo(handle, type,
            security_information, null,
            null, null, null, out SafeLocalAllocBuffer sd).MapDosErrorToStatus().CreateResult(throw_on_error, () => sd);
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
        return type switch
        {
            SeObjectType.File or SeObjectType.LMShare => NtType.GetTypeByType<NtFile>(),
            SeObjectType.RegistryKey or SeObjectType.RegistryWow6432Key or SeObjectType.RegistryWow6464Key => NtType.GetTypeByType<NtKey>(),
            SeObjectType.Service => NtType.GetTypeByName(ServiceUtils.SERVICE_NT_TYPE_NAME),
            SeObjectType.WmiGuid => NtType.GetTypeByType<NtEtwRegistration>(),
            SeObjectType.Ds or SeObjectType.DsAll => NtType.GetTypeByName(DirectoryServiceUtils.DS_NT_TYPE_NAME),
            SeObjectType.Printer => NtType.GetTypeByName(PrintSpoolerUtils.PRINTER_NT_TYPE_NAME),
            _ => null,
        };
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
        SecurityNativeMethods.LookupPrivilegeDisplayName(system_name, privilege_name, null, ref name_length, out int lang_id);
        if (name_length <= 0)
        {
            return  string.Empty;
        }

        StringBuilder builder = new(name_length + 1);
        name_length = builder.Capacity;
        if (SecurityNativeMethods.LookupPrivilegeDisplayName(system_name, privilege_name, builder, ref name_length, out lang_id))
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
        using var sid_buffer = sid.ToSafeBuffer();
        LSA_SID_NAME_MAPPING_OPERATION_ADD_INPUT input = new()
        {
            Sid = sid_buffer.DangerousGetHandle(),
            DomainName = new UnicodeStringIn(domain)
        };
        if (!string.IsNullOrEmpty(name))
        {
            input.AccountName = new UnicodeStringIn(name);
        }

        using var input_buffer = input.ToBuffer();
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
        LSA_SID_NAME_MAPPING_OPERATION_REMOVE_INPUT input = new()
        {
            DomainName = new UnicodeStringIn(domain)
        };
        if (name != null)
        {
            input.AccountName = new UnicodeStringIn(name);
        }

        using var input_buffer = input.ToBuffer();
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
        using var pwd = new SecureStringMarshalBuffer(password);
        return SecurityNativeMethods.LogonUser(user, domain, pwd, type, provider,
            out SafeKernelObjectHandle handle).CreateWin32Result(throw_on_error, () => new NtToken(handle));
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

        TokenGroupsBuilder builder = new();
        foreach (var group in groups)
        {
            builder.AddGroup(group.Sid, group.Attributes);
        }

        using var group_buffer = builder.ToBuffer();
        using var pwd = new SecureStringMarshalBuffer(password);
        return SecurityNativeMethods.LogonUserExExW(user, domain, pwd, type, provider, group_buffer,
            out SafeKernelObjectHandle token, null, null, null, null)
            .CreateWin32Result(throw_on_error, () => new NtToken(token));
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
        using var policy = LsaPolicy.Open(LsaPolicyAccessRights.LookupNames, throw_on_error);
        if (!policy.IsSuccess)
        {
            return policy.Cast<SidName>();
        }

        return policy.Result.LookupSids2(new Sid[] { sid }, LsaLookupSidOptionFlags.PreferInternetNames, throw_on_error).Map(e => e.First());
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

    /// <summary>
    /// Retrieve LSA private data.
    /// </summary>
    /// <param name="system_name">The system containing the LSA instance.</param>
    /// <param name="keyname">The name of the key.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The private data as bytes.</returns>
    public static NtResult<byte[]> LsaRetrievePrivateData(string system_name, string keyname, bool throw_on_error)
    {
        if (keyname is null)
        {
            throw new ArgumentNullException(nameof(keyname));
        }

        using var policy = LsaPolicy.Open(system_name, Policy.LsaPolicyAccessRights.GetPrivateInformation, throw_on_error);
        if (!policy.IsSuccess)
            return policy.Cast<byte[]>();
        return policy.Result.RetrievePrivateData(keyname, throw_on_error);
    }

    /// <summary>
    /// Retrieve LSA private data.
    /// </summary>
    /// <param name="system_name">The system containing the LSA instance.</param>
    /// <param name="keyname">The name of the key.</param>
    /// <returns>The private data as bytes.</returns>
    public static byte[] LsaRetrievePrivateData(string system_name, string keyname)
    {
        return LsaRetrievePrivateData(system_name, keyname, true).Result;
    }

    /// <summary>
    /// Retrieve LSA private data.
    /// </summary>
    /// <param name="keyname">The name of the key.</param>
    /// <returns>The private data as bytes.</returns>
    public static byte[] LsaRetrievePrivateData(string keyname)
    {
        return LsaRetrievePrivateData(null, keyname);
    }

    /// <summary>
    /// Store LSA private data.
    /// </summary>
    /// <param name="system_name">The system containing the LSA instance.</param>
    /// <param name="keyname">The name of the key.</param>
    /// <param name="data">The data to store.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus LsaStorePrivateData(string system_name, string keyname, byte[] data, bool throw_on_error)
    {
        if (data is null)
        {
            throw new ArgumentNullException(nameof(data));
        }

        using var policy = LsaPolicy.Open(system_name, LsaPolicyAccessRights.CreateSecret, throw_on_error);
        if (!policy.IsSuccess)
            return policy.Status;

        return policy.Result.StorePrivateData(keyname, data, throw_on_error);
    }

    /// <summary>
    /// Store LSA private data.
    /// </summary>
    /// <param name="system_name">The system containing the LSA instance.</param>
    /// <param name="keyname">The name of the key.</param>
    /// <param name="data">The data to store.</param>
    public static void LsaStorePrivateData(string system_name, string keyname, byte[] data)
    {
        LsaStorePrivateData(system_name, keyname, data, true);
    }

    /// <summary>
    /// Store LSA private data.
    /// </summary>
    /// <param name="keyname">The name of the key.</param>
    /// <param name="data">The data to store.</param>
    public static void LsaStorePrivateData(string keyname, byte[] data)
    {
        LsaStorePrivateData(null, keyname, data);
    }

    /// <summary>
    /// Delete LSA private data.
    /// </summary>
    /// <param name="system_name">The system containing the LSA instance.</param>
    /// <param name="keyname">The name of the key.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus LsaDeletePrivateData(string system_name, string keyname, bool throw_on_error)
    {
        using var policy = LsaPolicy.Open(system_name, LsaPolicyAccessRights.MaximumAllowed, throw_on_error);
        if (!policy.IsSuccess)
            return policy.Status;

        return policy.Result.StorePrivateData(keyname, null, throw_on_error);
    }

    /// <summary>
    /// Delete LSA private data.
    /// </summary>
    /// <param name="system_name">The system containing the LSA instance.</param>
    /// <param name="keyname">The name of the key.</param>
    public static void LsaDeletePrivateData(string system_name, string keyname)
    {
        LsaDeletePrivateData(system_name, keyname, true);
    }

    /// <summary>
    /// Delete LSA private data.
    /// </summary>
    /// <param name="keyname">The name of the key.</param>
    public static void LsaDeletePrivateData(string keyname)
    {
        LsaDeletePrivateData(null, keyname);
    }

    /// <summary>
    /// Set call flags for SSPI.
    /// </summary>
    /// <param name="flags">The flags to set.</param>
    public static void SetCallFlags(int flags)
    {
        SecurityNativeMethods.SeciAllocateAndSetCallFlags(flags, out bool _).CheckResult(true);
    }

    /// <summary>
    /// Logon a user using S4U
    /// </summary>
    /// <param name="user">The username.</param>
    /// <param name="realm">The user's realm.</param>
    /// <param name="logon_type"></param>
    /// <returns>The logged on token.</returns>
    public static NtToken GetLogonS4UToken(string user, string realm, SecurityLogonType logon_type)
    {
        switch (logon_type)
        {
            case SecurityLogonType.Batch:
            case SecurityLogonType.Interactive:
            case SecurityLogonType.Network:
                break;
            default:
                throw new ArgumentException("Invalid logon type for S4U");
        }

        return LsaLogonS4U(user, realm, logon_type);
    }

    /// <summary>
    /// Get the anonymous token.
    /// </summary>
    /// <param name="desired_access">The access rights for the opened token.</param>
    /// <returns>The anonymous token.</returns>
    public static NtToken GetAnonymousToken(TokenAccessRights desired_access)
    {
        using var imp = NtThread.Current.ImpersonateAnonymousToken();
        return NtToken.OpenThreadToken(NtThread.Current, true, false, desired_access);
    }

    /// <summary>
    /// Get the anonymous token.
    /// </summary>
    /// <returns>The anonymous token.</returns>
    public static NtToken GetAnonymousToken()
    {
        return GetAnonymousToken(TokenAccessRights.MaximumAllowed);
    }

    private static SafeKernelObjectHandle OpenClipboardToken(TokenAccessRights desired_access)
    {
        if (!SecurityNativeMethods.GetClipboardAccessToken(out SafeKernelObjectHandle handle, desired_access))
        {
            throw new NtException(NtStatus.STATUS_NO_TOKEN);
        }
        return handle;
    }

    /// <summary>
    /// Open the current clipboard token.
    /// </summary>
    /// <param name="desired_access"></param>
    /// <param name="throw_on_error"></param>
    /// <returns></returns>
    public static NtResult<NtToken> OpenClipboardToken(TokenAccessRights desired_access, bool throw_on_error)
    {
        if (SecurityNativeMethods.GetClipboardAccessToken(out SafeKernelObjectHandle handle, desired_access))
        {
            return NtToken.FromHandle(handle).CreateResult();
        }

        return NtStatus.STATUS_NO_TOKEN.CreateResultFromError<NtToken>(throw_on_error);
    }

    /// <summary>
    /// Get the token from the clipboard.
    /// </summary>
    /// <param name="desired_access">The access rights for the opened token.</param>
    /// <returns>The clipboard token.</returns>
    public static NtToken GetTokenFromClipboard(TokenAccessRights desired_access)
    {
        try
        {
            return NtToken.FromHandle(OpenClipboardToken(desired_access));
        }
        catch (NtException)
        {
            throw;
        }
        catch
        {
            throw new InvalidOperationException("GetClipboardAccessToken doesn't exist");
        }
    }

    /// <summary>
    /// Get the token from the clipboard.
    /// </summary>
    /// <returns>The clipboard token.</returns>
    public static NtToken GetTokenFromClipboard()
    {
        return GetTokenFromClipboard(TokenAccessRights.MaximumAllowed | TokenAccessRights.Query | TokenAccessRights.QuerySource
            | TokenAccessRights.ReadControl);
    }

    /// <summary>
    /// Derive a package sid from a name.
    /// </summary>
    /// <param name="name">The name of the package.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The derived Sid</returns>
    public static NtResult<Sid> DerivePackageSidFromName(string name, bool throw_on_error)
    {
        int hr = SecurityNativeMethods.DeriveAppContainerSidFromAppContainerName(name, out SafeSidBufferHandle sid);
        if (hr == 0)
        {
            using (sid)
            {
                Sid result = new(sid);
                NtSecurity.CachePackageName(result, name);
                return NtSecurity.CacheSidName(result, string.Empty, name,
                    SidNameSource.Package, SidNameUse.User).CreateResult();
            }
        }

        return ((NtStatus)hr).CreateResultFromError<Sid>(throw_on_error);
    }

    /// <summary>
    /// Derive a package sid from a name.
    /// </summary>
    /// <param name="name">The name of the package.</param>
    /// <returns>The derived Sid</returns>
    public static Sid DerivePackageSidFromName(string name)
    {
        return DerivePackageSidFromName(name, true).Result;
    }

    /// <summary>
    /// Derive a restricted package sid from an existing pacakge sid.
    /// </summary>
    /// <param name="package_sid">The base package sid.</param>
    /// <param name="restricted_name">The restricted name for the sid.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The derived Sid.</returns>
    public static NtResult<Sid> DeriveRestrictedPackageSidFromSid(Sid package_sid, string restricted_name, bool throw_on_error)
    {
        using var sid_buf = package_sid.ToSafeBuffer();
        int hr = SecurityNativeMethods.DeriveRestrictedAppContainerSidFromAppContainerSidAndRestrictedName(sid_buf,
            restricted_name, out SafeSidBufferHandle sid);
        if (hr == 0)
        {
            using (sid)
            {
                Sid result = new(sid);
                NtSecurity.CacheSidName(result, string.Empty, $"{package_sid.Name}/{restricted_name}",
                    SidNameSource.Package, SidNameUse.User);
                return result.CreateResult();
            }
        }
        return ((NtStatus)hr).CreateResultFromError<Sid>(throw_on_error);
    }

    /// <summary>
    /// Derive a restricted package sid from an existing pacakge sid.
    /// </summary>
    /// <param name="package_sid">The base package sid.</param>
    /// <param name="restricted_name">The restricted name for the sid.</param>
    /// <returns>The derived Sid.</returns>
    public static Sid DeriveRestrictedPackageSidFromSid(Sid package_sid, string restricted_name)
    {
        return DeriveRestrictedPackageSidFromSid(package_sid, restricted_name, true).Result;
    }

    /// <summary>
    /// Derive a restricted package sid from an existing package sid.
    /// </summary>
    /// <param name="base_name">The base package name.</param>
    /// <param name="restricted_name">The restricted name for the sid.</param>
    /// <returns>The derived Sid.</returns>
    public static Sid DeriveRestrictedPackageSidFromName(string base_name, string restricted_name)
    {
        return DeriveRestrictedPackageSidFromSid(DerivePackageSidFromName(base_name), restricted_name);
    }

    /// <summary>
    /// Get the package SID from a name.
    /// </summary>
    /// <param name="name">The name of the package, can be either an SDDL SID or a package name.</param>
    /// <returns>The derived SID.</returns>
    public static Sid GetPackageSidFromName(string name)
    {
        var package_sid = Sid.Parse(name, false);
        if (package_sid.IsSuccess)
        {
            if (!NtSecurity.IsPackageSid(package_sid.Result))
            {
                throw new ArgumentException($"Invalid package SID {name}");
            }
            return package_sid.Result;
        }
        else
        {
            return DerivePackageSidFromName(name);
        }
    }

    /// <summary>
    /// Get a safer token.
    /// </summary>
    /// <param name="token">The base token.</param>
    /// <param name="level">The safer level to use.</param>
    /// <param name="make_inert">True to make the token inert.</param>
    /// <returns>The safer token.</returns>
    public static NtToken GetTokenFromSaferLevel(NtToken token, SaferLevelId level, bool make_inert)
    {
        using SaferLevel level_obj = SaferLevel.Open(SaferScopeId.User, level);
        using NtToken duptoken = token.Duplicate(TokenAccessRights.GenericRead | TokenAccessRights.GenericExecute);
        return level_obj.ComputeToken(duptoken, make_inert ? SaferComputeTokenFlags.MakeInert : 0);
    }

    /// <summary>
    /// Create an AppContainer token using the CreateAppContainerToken API.
    /// </summary>
    /// <param name="token">The token to base the new token on. Can be null.</param>
    /// <param name="appcontainer_sid">The AppContainer package SID.</param>
    /// <param name="capabilities">List of capabilities.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The appcontainer token.</returns>
    /// <remarks>This exported function was only introduced in RS3</remarks>
    [SupportedVersion(SupportedVersion.Windows10_RS3)]
    public static NtResult<NtToken> CreateAppContainerToken(NtToken token, Sid appcontainer_sid,
        IEnumerable<Sid> capabilities, bool throw_on_error)
    {
        using var resources = new DisposableList();
        return SecurityNativeMethods.CreateAppContainerToken(token.GetHandle(),
            SECURITY_CAPABILITIES.Create(appcontainer_sid, capabilities ?? new Sid[0], resources),
            out SafeKernelObjectHandle new_token).CreateWin32Result(throw_on_error, () => NtToken.FromHandle(new_token));
    }

    /// <summary>
    /// Create an AppContainer token using the CreateAppContainerToken API.
    /// </summary>
    /// <param name="token">The token to base the new token on. Can be null.</param>
    /// <param name="appcontainer_sid">The AppContainer package SID.</param>
    /// <param name="capabilities">List of capabilities.</param>
    /// <returns>The appcontainer token.</returns>
    /// <remarks>This exported function was only introduced in RS3</remarks>
    public static NtToken CreateAppContainerToken(NtToken token, Sid appcontainer_sid,
        IEnumerable<Sid> capabilities)
    {
        return CreateAppContainerToken(token, appcontainer_sid, capabilities, true).Result;
    }

    /// <summary>
    /// Create an AppContainer token using the CreateAppContainerToken API.
    /// </summary>
    /// <param name="appcontainer_sid">The AppContainer package SID.</param>
    /// <param name="capabilities">List of capabilities.</param>
    /// <returns>The appcontainer token.</returns>
    /// <remarks>This exported function was only introduced in RS3</remarks>
    public static NtToken CreateAppContainerToken(Sid appcontainer_sid,
        IEnumerable<Sid> capabilities)
    {
        return CreateAppContainerToken(null, appcontainer_sid, capabilities);
    }

    /// <summary>
    /// Logon user using Kerberos Ticket.
    /// </summary>
    /// <param name="type">The type of logon token.</param>
    /// <param name="service_ticket">The service ticket.</param>
    /// <param name="tgt_ticket">Optional TGT.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The logged on token.</returns>
    public static NtResult<NtToken> LsaLogonTicket(SecurityLogonType type, KerberosTicket service_ticket, KerberosCredential tgt_ticket, bool throw_on_error)
    {
        if (service_ticket is null)
        {
            throw new ArgumentNullException(nameof(service_ticket));
        }

        using var logon_handle = LsaLogonHandle.Connect(throw_on_error);
        if (!logon_handle.IsSuccess)
            return logon_handle.Cast<NtToken>();
        var creds = new KerberosTicketLogonCredentials()
        {
            ServiceTicket = service_ticket,
            TicketGrantingTicket = tgt_ticket
        };
        using var result = logon_handle.Result.LsaLogonUser(type, AuthenticationPackage.KERBEROS_NAME, "KTIK",
            new TokenSource("NT.NET"), creds, null, throw_on_error);
        return result.Map(r => r.Token.Duplicate());
    }

    /// <summary>
    /// Logon user using Kerberos Ticket.
    /// </summary>
    /// <param name="type">The type of logon token.</param>
    /// <param name="service_ticket">The service ticket.</param>
    /// <param name="tgt_ticket">Optional TGT.</param>
    /// <returns>The logged on token.</returns>
    public static NtToken LsaLogonTicket(SecurityLogonType type, KerberosTicket service_ticket, KerberosCredential tgt_ticket)
    {
        return LsaLogonTicket(type, service_ticket, tgt_ticket, true).Result;
    }

    /// <summary>
    /// Logon user using Kerberos Ticket.
    /// </summary>
    /// <param name="type">The type of logon token.</param>
    /// <param name="service_ticket">The service ticket.</param>
    /// <param name="tgt_ticket">Optional TGT.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The logged on token.</returns>
    public static NtResult<NtToken> LsaLogonTicket(SecurityLogonType type, byte[] service_ticket, byte[] tgt_ticket, bool throw_on_error)
    {
        if (service_ticket is null)
        {
            throw new ArgumentNullException(nameof(service_ticket));
        }

        if (KerberosTicket.TryParse(service_ticket, out KerberosTicket ticket))
        {
            throw new ArgumentException("Invalid service ticket.", nameof(service_ticket));
        }

        KerberosCredential credential = null;
        if (tgt_ticket != null)
        {
            if (!KerberosCredential.TryParse(tgt_ticket, null, out credential))
            {
                throw new ArgumentException("Invalid ticket granting ticket.", nameof(tgt_ticket));
            }
        }
        return LsaLogonTicket(type, ticket, credential, throw_on_error);
    }

    /// <summary>
    /// Logon user using Kerberos Ticket.
    /// </summary>
    /// <param name="type">The type of logon token.</param>
    /// <param name="service_ticket">The service ticket.</param>
    /// <param name="tgt_ticket">Optional TGT.</param>
    /// <returns>The logged on token.</returns>
    public static NtToken LsaLogonTicket(SecurityLogonType type, byte[] service_ticket, byte[] tgt_ticket)
    {
        return LsaLogonTicket(type, service_ticket, tgt_ticket, true).Result;
    }

    /// <summary>
    /// Logon user using S4U
    /// </summary>
    /// <param name="user">The username.</param>
    /// <param name="realm">The user's realm.</param>
    /// <param name="type">The type of logon token.</param>
    /// <param name="auth_package">The name of the auth package to user.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The logged on token.</returns>
    public static NtResult<NtToken> LsaLogonS4U(string user, string realm, SecurityLogonType type, string auth_package, bool throw_on_error)
    {
        if (user is null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        if (realm is null)
        {
            throw new ArgumentNullException(nameof(realm));
        }

        using var logon_handle = LsaLogonHandle.Connect(throw_on_error);
        if (!logon_handle.IsSuccess)
            return logon_handle.Cast<NtToken>();
        KerberosS4ULogonCredentials creds = new()
        {
            ClientRealm = realm,
            ClientUpn = user
        };
        using var result = logon_handle.Result.LsaLogonUser(type, auth_package, "S4U",
            new TokenSource("NT.NET"), creds, null, throw_on_error);
        return result.Map(r => r.Token.Duplicate());
    }

    /// <summary>
    /// Logon user using S4U
    /// </summary>
    /// <param name="user">The username.</param>
    /// <param name="realm">The user's realm.</param>
    /// <param name="type">The type of logon token.</param>
    /// <param name="auth_package">The name of the auth package to user.</param>
    /// <returns>The logged on token.</returns>
    public static NtToken LsaLogonS4U(string user, string realm, SecurityLogonType type, string auth_package)
    {
        return LsaLogonS4U(user, realm, type, auth_package, true).Result;
    }

    /// <summary>
    /// Logon user using S4U
    /// </summary>
    /// <param name="user">The username.</param>
    /// <param name="realm">The user's realm.</param>
    /// <param name="type">The type of logon token.</param>
    /// <returns>The logged on token.</returns>
    public static NtToken LsaLogonS4U(string user, string realm, SecurityLogonType type)
    {
        return LsaLogonS4U(user, realm, type, AuthenticationPackage.NEGOSSP_NAME);
    }

    /// <summary>
    /// Get a logon session.
    /// </summary>
    /// <param name="luid">The logon session ID.</param>
    /// <param name="throw_on_error">True to thrown on error.</param>
    /// <returns>The logon session.</returns>
    public static NtResult<LogonSession> GetLogonSession(Luid luid, bool throw_on_error)
    {
        return LogonSession.GetLogonSession(luid, throw_on_error);
    }

    /// <summary>
    /// Get a logon session.
    /// </summary>
    /// <param name="luid">The logon session ID.</param>
    /// <returns>The logon session.</returns>
    public static LogonSession GetLogonSession(Luid luid)
    {
        return GetLogonSession(luid, true).Result;
    }

    /// <summary>
    /// Get the logon session LUIDs
    /// </summary>
    /// <param name="throw_on_error">True throw on error.</param>
    /// <returns>The list of logon sessions. Only returns ones you can access.</returns>
    public static NtResult<IEnumerable<Luid>> GetLogonSessionIds(bool throw_on_error)
    {
        return LogonSession.GetLogonSessionIds(throw_on_error);
    }

    /// <summary>
    /// Get the logon session LUIDs
    /// </summary>
    /// <returns>The list of logon sessions. Only returns ones you can access.</returns>
    public static IEnumerable<Luid> GetLogonSessionIds()
    {
        return GetLogonSessionIds(true).Result;
    }

    /// <summary>
    /// Get the logon sessions.
    /// </summary>
    /// <param name="throw_on_error">True throw on error.</param>
    /// <returns>The list of logon sessions. Only returns ones you can access.</returns>
    public static NtResult<IEnumerable<LogonSession>> GetLogonSessions(bool throw_on_error)
    {
        return LogonSession.GetLogonSessions(throw_on_error);
    }

    /// <summary>
    /// Get the logon sessions.
    /// </summary>
    /// <returns>The list of logon sessions.</returns>
    public static IEnumerable<LogonSession> GetLogonSessions()
    {
        return GetLogonSessions(true).Result;
    }

    /// <summary>
    /// Get account rights assigned to a SID.
    /// </summary>
    /// <param name="sid">The SID to query.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The list of account rights.</returns>
    public static NtResult<IEnumerable<AccountRight>> GetAccountRights(Sid sid, bool throw_on_error)
    {
        return AccountRight.GetAccountRights(null, sid, throw_on_error);
    }

    /// <summary>
    /// Get account rights assigned to a SID.
    /// </summary>
    /// <param name="sid">The SID to query.</param>
    /// <returns>The list of account rights.</returns>
    public static IEnumerable<AccountRight> GetAccountRights(Sid sid)
    {
        return GetAccountRights(sid, true).Result;
    }

    /// <summary>
    /// Get SIDs associated with an account right.
    /// </summary>
    /// <param name="account_right">The name of the account right, such as SeImpersonatePrivilege.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The list of SIDs assigned to the account right.</returns>
    public static NtResult<IEnumerable<Sid>> GetAccountRightSids(string account_right, bool throw_on_error)
    {
        return AccountRight.GetSids(null, account_right, throw_on_error).Cast<IEnumerable<Sid>>();
    }

    /// <summary>
    /// Get SIDs associated with an account right.
    /// </summary>
    /// <param name="account_right">The name of the account right, such as SeImpersonatePrivilege.</param>
    /// <returns>The list of SIDs assigned to the account right.</returns>
    public static IEnumerable<Sid> GetAccountRightSids(string account_right)
    {
        return GetAccountRightSids(account_right, true).Result;
    }

    /// <summary>
    /// Get SIDs associated with an account right.
    /// </summary>
    /// <param name="privilege">The account right privilege to query.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The list of SIDs assigned to the account right.</returns>
    public static NtResult<IEnumerable<Sid>> GetAccountRightSids(TokenPrivilegeValue privilege, bool throw_on_error)
    {
        return GetAccountRightSids(privilege.ToString(), throw_on_error);
    }

    /// <summary>
    /// Get SIDs associated with an account right.
    /// </summary>
    /// <param name="privilege">The account right privilege to query.</param>
    /// <returns>The list of SIDs assigned to the account right.</returns>
    public static IEnumerable<Sid> GetAccountRightSids(TokenPrivilegeValue privilege)
    {
        return GetAccountRightSids(privilege, true).Result;
    }

    /// <summary>
    /// Get SIDs associated with an account right.
    /// </summary>
    /// <param name="logon_type">The logon account right to query.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The list of SIDs assigned to the account right.</returns>
    public static NtResult<IEnumerable<Sid>> GetAccountRightSids(AccountRightLogonType logon_type, bool throw_on_error)
    {
        return GetAccountRightSids(logon_type.ToString(), throw_on_error);
    }

    /// <summary>
    /// Get SIDs associated with an account right.
    /// </summary>
    /// <param name="logon_type">The logon account right to query.</param>
    /// <returns>The list of SIDs assigned to the account right.</returns>
    public static IEnumerable<Sid> GetAccountRightSids(AccountRightLogonType logon_type)
    {
        return GetAccountRightSids(logon_type, true).Result;
    }

    /// <summary>
    /// Get account rights.
    /// </summary>
    /// <param name="type">Specify the type of account rights to get.</param>
    /// <returns>Account rights.</returns>
    public static IEnumerable<AccountRight> GetAccountRights(AccountRightType type)
    {
        IEnumerable<string> rights = new string[0];
        if (type == AccountRightType.All || type == AccountRightType.Privilege)
        {
            rights = Enum.GetNames(typeof(TokenPrivilegeValue));
        }
        if (type == AccountRightType.All || type == AccountRightType.Logon)
        {
            rights = rights.Concat(Enum.GetNames(typeof(AccountRightLogonType)));
        }

        return rights.Select(n => new AccountRight(null, n, null)).ToList().AsReadOnly();
    }

    /// <summary>
    /// Get all account rights.
    /// </summary>
    /// <returns>All account rights.</returns>
    public static IEnumerable<AccountRight> GetAccountRights()
    {
        return GetAccountRights(AccountRightType.All);
    }

    /// <summary>
    /// Add account rights to the user.
    /// </summary>
    /// <param name="sid">The user SID to add.</param>
    /// <param name="account_rights">The list of account rights.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus AddAccountRights(Sid sid, IEnumerable<string> account_rights, bool throw_on_error)
    {
        return AccountRight.AddAccountRights(null, sid, account_rights, throw_on_error);
    }

    /// <summary>
    /// Add account rights to the user.
    /// </summary>
    /// <param name="sid">The user SID to add.</param>
    /// <param name="account_rights">The list of account rights.</param>
    /// <returns>The NT status code.</returns>
    public static void AddAccountRights(Sid sid, IEnumerable<string> account_rights)
    {
        AddAccountRights(sid, account_rights, true);
    }

    /// <summary>
    /// Add account rights as privileges.
    /// </summary>
    /// <param name="sid">The user SID to add.</param>
    /// <param name="privileges">The list of account privileges.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus AddAccountRights(Sid sid, TokenPrivilegeValue[] privileges, bool throw_on_error)
    {
        return AddAccountRights(sid, privileges.Select(p => p.ToString()), throw_on_error);
    }

    /// <summary>
    /// Add account rights as privileges.
    /// </summary>
    /// <param name="sid">The user SID to add.</param>
    /// <param name="privileges">The list of account privileges.</param>
    public static void AddAccountRights(Sid sid, params TokenPrivilegeValue[] privileges)
    {
        AddAccountRights(sid, privileges, true);
    }

    /// <summary>
    /// Add account rights as privileges.
    /// </summary>
    /// <param name="sid">The user SID to add.</param>
    /// <param name="logon_type">The list of account logon types.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus AddAccountRights(Sid sid, AccountRightLogonType[] logon_type, bool throw_on_error)
    {
        return AddAccountRights(sid, logon_type.Select(p => p.ToString()), throw_on_error);
    }

    /// <summary>
    /// Add account rights as privileges.
    /// </summary>
    /// <param name="sid">The user SID to add.</param>
    /// <param name="logon_type">The list of account logon types.</param>
    public static void AddAccountRights(Sid sid, params AccountRightLogonType[] logon_type)
    {
        AddAccountRights(sid, logon_type, true);
    }

    /// <summary>
    /// Remove account rights from a user.
    /// </summary>
    /// <param name="sid">The user SID to remove.</param>
    /// <param name="account_rights">The list of account rights.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus RemoveAccountRights(Sid sid, IEnumerable<string> account_rights, bool throw_on_error)
    {
        return AccountRight.RemoveAccountRights(null, sid, false, account_rights, throw_on_error);
    }

    /// <summary>
    /// Remove account rights from a user.
    /// </summary>
    /// <param name="sid">The user SID to remove.</param>
    /// <param name="account_rights">The list of account rights.</param>
    public static void RemoveAccountRights(Sid sid, IEnumerable<string> account_rights)
    {
        RemoveAccountRights(sid, account_rights, true);
    }

    /// <summary>
    /// Remove account rights from a user.
    /// </summary>
    /// <param name="sid">The user SID to remove.</param>
    /// <param name="privileges">The list of privileges.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus RemoveAccountRights(Sid sid, TokenPrivilegeValue[] privileges, bool throw_on_error)
    {
        return RemoveAccountRights(sid, privileges.Select(p => p.ToString()), throw_on_error);
    }

    /// <summary>
    /// Remove account rights from a user.
    /// </summary>
    /// <param name="sid">The user SID to remove.</param>
    /// <param name="privileges">The list of account privileges.</param>
    public static void RemoveAccountRights(Sid sid, params TokenPrivilegeValue[] privileges)
    {
        RemoveAccountRights(sid, privileges, true);
    }

    /// <summary>
    /// Remove account rights from a user.
    /// </summary>
    /// <param name="sid">The user SID to remove.</param>
    /// <param name="logon_type">The list of account rights.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The NT status code.</returns>
    public static NtStatus RemoveAccountRights(Sid sid, AccountRightLogonType[] logon_type, bool throw_on_error)
    {
        return RemoveAccountRights(sid, logon_type.Select(p => p.ToString()), throw_on_error);
    }

    /// <summary>
    /// Remove account rights from a user.
    /// </summary>
    /// <param name="sid">The user SID to remove.</param>
    /// <param name="privileges">The list of account rights.</param>
    public static void RemoveAccountRights(Sid sid, params AccountRightLogonType[] privileges)
    {
        RemoveAccountRights(sid, privileges, true);
    }

    /// <summary>
    /// Get a mask dictionary for a type. 
    /// </summary>
    /// <param name="access_type">The enumerated type to query for names.</param>
    /// <param name="valid_access">The valid access.</param>
    /// <returns>A dictionary mapping a mask value to a name.</returns>
    public static Dictionary<uint, string> GetMaskDictionary(Type access_type, AccessMask valid_access)
    {
        return GetMaskDictionary(access_type, valid_access, false);
    }

    /// <summary>
    /// Get a mask dictionary for a type. 
    /// </summary>
    /// <param name="access_type">The enumerated type to query for names.</param>
    /// <param name="valid_access">The valid access.</param>
    /// <param name="sdk_names">Specify to get the SDK name instead of a formatting enumerated name.</param>
    /// <returns>A dictionary mapping a mask value to a name.</returns>
    public static Dictionary<uint, string> GetMaskDictionary(Type access_type, AccessMask valid_access, bool sdk_names)
    {
        Dictionary<uint, string> access = new();
        AddEnumToDictionary(access, access_type, valid_access.Access, sdk_names);
        return access;
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

    private static bool IsValidMask(uint mask, uint valid_mask)
    {
        if (mask == 0)
        {
            return false;
        }

        // Filter out generic access etc.
        if ((mask & ~valid_mask) != 0)
        {
            return false;
        }

        // Check if the mask only has a single bit set.
        if ((mask & (mask - 1)) != 0)
        {
            return false;
        }

        return true;
    }

    private static void AddEnumToDictionary(Dictionary<uint, string> access, Type enumType, uint valid_mask, bool sdk_names)
    {
        Regex re = new("([A-Z])");

        foreach (uint mask in Enum.GetValues(enumType))
        {
            if (IsValidMask(mask, valid_mask))
            {
                string name = sdk_names ? NtSecurity.GetSDKName(enumType, mask)
                    : re.Replace(Enum.GetName(enumType, mask), " $1").Trim();
                access.Add(mask, name);
            }
        }
    }
    #endregion
}
