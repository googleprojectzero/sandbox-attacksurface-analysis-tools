//  Copyright 2016 Google Inc. All Rights Reserved.
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

using NtCoreLib.Security.Authorization;
using NtCoreLib.Win32.Security.Interop;
using System;
using System.Collections.Generic;

namespace NtCoreLib.Win32.Security.Authorization.AclUI;

/// <summary>
/// System dialog to edit a security descriptor.
/// </summary>
public sealed class EditSecurityDescriptorDialog : IDisposable
{
    #region Private Members
    private readonly SecurityInformationImpl _impl;
    #endregion

    #region Constructors
    /// <summary>
    /// Display the edit security dialog.
    /// </summary>
    /// <param name="handle">NT object to display the security.</param>
    /// <param name="object_name">The name of the object to display.</param>
    /// <param name="read_only">True to force the UI to read only.</param>
    public EditSecurityDescriptorDialog(NtObject handle, string object_name, bool read_only)
    {
        Dictionary<uint, string> access = Win32Security.GetMaskDictionary(handle.NtType.AccessRightsType, handle.NtType.ValidAccess);
        _impl = new(object_name, handle, access,
           handle.NtType.GenericMapping, read_only);
    }

    /// <summary>
    /// Display the edit security dialog.
    /// </summary>
    /// <param name="name">The name of the object to display.</param>
    /// <param name="sd">The security descriptor to display.</param>
    /// <param name="type">The NT type of the object.</param>
    public EditSecurityDescriptorDialog(string name, SecurityDescriptor sd, NtType type) 
        : this(name, sd, type.AccessRightsType, type.ValidAccess, type.GenericMapping)
    {
    }

    /// <summary>
    /// Display the edit security dialog.
    /// </summary>
    /// <param name="name">The name of the object to display.</param>
    /// <param name="sd">The security descriptor to display.</param>
    /// <param name="access_type">An enumerated type for the access mask.</param>
    /// <param name="generic_mapping">Generic mapping for the access rights.</param>
    /// <param name="valid_access">Valid access mask for the access rights.</param>
    public EditSecurityDescriptorDialog(string name, SecurityDescriptor sd,
        Type access_type, AccessMask valid_access, GenericMapping generic_mapping)
    {
        Dictionary<uint, string> access = Win32Security.GetMaskDictionary(access_type, valid_access);
        _impl = new SecurityInformationImpl(name, sd, access, generic_mapping);
    }
    #endregion

    #region Public Methods
    /// <summary>
    /// Show the edit security dialog.
    /// </summary>
    /// <param name="parent_hwnd">The parent window handle.</param>
    /// <returns>True if not cancelled.</returns>
    public bool Show(IntPtr parent_hwnd = default)
    {
        return SecurityNativeMethods.EditSecurity(parent_hwnd, _impl);
    }

    /// <summary>
    /// Dispose the dialog.
    /// </summary>
    public void Dispose()
    {
        _impl.Dispose();
    }
    #endregion
}