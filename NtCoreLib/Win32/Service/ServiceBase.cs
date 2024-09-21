//  Copyright 2021 Google Inc. All Rights Reserved.
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

#nullable enable

using NtCoreLib.Security.Authorization;
using NtCoreLib.Win32.Service.Interop;
using System;

namespace NtCoreLib.Win32.Service;

/// <summary>
/// Base class for Service and SCM objects.
/// </summary>
/// <typeparam name="AccessEnum"></typeparam>
public abstract class ServiceBase<AccessEnum> : IDisposable, INtObjectSecurity where AccessEnum : Enum
{
    #region Private Protected Members
    private protected readonly string _name;
    private protected readonly string? _machine_name;
    private protected readonly NtType _type;

    private protected ServiceBase(SafeServiceHandle handle, string name, string? machine_name, AccessEnum granted_access, string type_name)
    {
        Handle = handle;
        _name = name;
        _machine_name = machine_name;
        GrantedAccess = granted_access;
        _type = NtType.GetTypeByName(type_name);
    }
    #endregion

    #region Public Properties
    /// <summary>
    /// Get the granted access for this object.
    /// </summary>
    public AccessEnum GrantedAccess { get; }
    #endregion

    #region Public Methods
    /// <summary>
    /// Dispose the object.
    /// </summary>
    public void Dispose()
    {
        Handle.Close();
    }
    #endregion

    #region Internal Members
    internal SafeServiceHandle Handle { get; }
    #endregion

    #region INtObjectSecurity Implementation
    NtType INtObjectSecurity.NtType => _type;

    string INtObjectSecurity.ObjectName => string.IsNullOrEmpty(_machine_name) ? _name : $@"{_name} (\\{_machine_name})";

    bool INtObjectSecurity.IsContainer => false;

    SecurityDescriptor INtObjectSecurity.SecurityDescriptor => GetSecurityDescriptor(SafeServiceHandle.DEFAULT_SECURITY_INFORMATION);

    bool INtObjectSecurity.IsAccessMaskGranted(AccessMask access)
    {
        AccessMask access_mask = GrantedAccess;
        if (access_mask.IsAllAccessGranted(access))
            return true;
        // We can't tell if we really have access or not, so just assume we do.
        return access_mask.IsAccessGranted(GenericAccessRights.MaximumAllowed);
    }

    /// <summary>
    /// Get the security descriptor specifying which parts to retrieve
    /// </summary>
    /// <param name="security_information">What parts of the security descriptor to retrieve</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The security descriptor</returns>
    public NtResult<SecurityDescriptor> GetSecurityDescriptor(SecurityInformation security_information, bool throw_on_error)
    {
        return Handle.GetSecurityDescriptor(_type, security_information, throw_on_error);
    }

    /// <summary>
    /// Get the security descriptor specifying which parts to retrieve
    /// </summary>
    /// <param name="security_information">What parts of the security descriptor to retrieve</param>
    /// <returns>The security descriptor</returns>
    public SecurityDescriptor GetSecurityDescriptor(SecurityInformation security_information)
    {
        return GetSecurityDescriptor(security_information, true).Result;
    }

    /// <summary>
    /// Set the object's security descriptor
    /// </summary>
    /// <param name="security_descriptor">The security descriptor to set.</param>
    /// <param name="security_information">What parts of the security descriptor to set</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    public NtStatus SetSecurityDescriptor(SecurityDescriptor security_descriptor, SecurityInformation security_information, bool throw_on_error)
    {
        return Handle.SetSecurityDescriptor(security_information, security_descriptor, throw_on_error);
    }

    /// <summary>
    /// Set the object's security descriptor
    /// </summary>
    /// <param name="security_descriptor">The security descriptor to set.</param>
    /// <param name="security_information">What parts of the security descriptor to set</param>
    public void SetSecurityDescriptor(SecurityDescriptor security_descriptor, SecurityInformation security_information)
    {
        SetSecurityDescriptor(security_descriptor, security_information, true);
    }
    #endregion
}
