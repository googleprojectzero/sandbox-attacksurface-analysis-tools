//  Copyright 2017 Google Inc. All Rights Reserved.
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

using NtCoreLib;
using NtCoreLib.Security;
using NtCoreLib.Security.Authorization;
using System;

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
///<para type="description">General Access check result.</para>
/// </summary>
public class CommonAccessCheckResult
{
    /// <summary>
    /// The name of the object which was accessed (depends on the type).
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// Name of the type accessed.
    /// </summary>
    public string TypeName { get; }

    /// <summary>
    /// Granted access.
    /// </summary>
    public AccessMask GrantedAccess { get; }

    /// <summary>
    /// Get granted access as a type specific string
    /// </summary>
    public string GrantedAccessString { get; }

    /// <summary>
    /// Get granted access as generic access string.
    /// </summary>
    public string GrantedGenericAccessString { get; }

    /// <summary>
    /// The generic mapping associated with this type.
    /// </summary>
    public GenericMapping GenericMapping { get; }

    /// <summary>
    /// The security descriptor associated with this access check.
    /// </summary>
    public string SecurityDescriptor { get; }

    /// <summary>
    /// The security descriptor associated with this access check in base64 format.
    /// </summary>
    public string SecurityDescriptorBase64 { get; }

    /// <summary>
    /// The SID owner of the resource from the security descriptor.
    /// </summary>
    public string Owner { get; }

    /// <summary>
    /// Information the token used in the access check.
    /// </summary>
    public TokenInformation TokenInfo { get; }

    /// <summary>
    /// Was read access granted?
    /// </summary>
    public bool IsRead { get; }

    /// <summary>
    /// Was write access granted?
    /// </summary>
    public bool IsWrite { get; }

    /// <summary>
    /// Was execute access granted?
    /// </summary>
    public bool IsExecute { get; }

    /// <summary>
    /// Was all access granted?
    /// </summary>
    public bool IsAll { get; }

    /// <summary>
    /// Is the resource being access a directory.
    /// </summary>
    public bool IsDirectory { get; }

    /// <summary>
    /// Unique key for access check result (based on TokenId)
    /// </summary>
    public long TokenId { get; }

    /// <summary>
    /// Indicates if the security descriptor has an integrity label.
    /// </summary>
    public bool HasMandatoryLabel { get; }

    /// <summary>
    /// Indicates if the security descriptor has a process trust label.
    /// </summary>
    public bool HasProcessTrustLabel { get; }

    internal CommonAccessCheckResult(string name, string type_name, AccessMask granted_access,
        GenericMapping generic_mapping, SecurityDescriptor sd, 
        Type enum_type, bool is_directory, TokenInformation token_info)
    {
        Name = name;
        TypeName = type_name;
        GrantedAccess = granted_access;
        GenericMapping = generic_mapping;
        TokenInfo = token_info;
        SecurityDescriptor = sd?.ToSddl(SecurityInformation.All, false).GetResultOrDefault() ?? string.Empty;
        SecurityDescriptorBase64 = sd?.ToBase64() ?? string.Empty;
        Owner = sd?.Owner?.Sid.ToString() ?? string.Empty;
        IsRead = generic_mapping.HasRead(granted_access);
        IsWrite = generic_mapping.HasWrite(granted_access) 
            || granted_access.IsAccessGranted(GenericAccessRights.WriteDac) 
            || granted_access.IsAccessGranted(GenericAccessRights.WriteOwner)
            || granted_access.IsAccessGranted(GenericAccessRights.Delete);
        IsExecute = generic_mapping.HasExecute(granted_access);
        IsAll = generic_mapping.HasAll(granted_access);
        GrantedAccessString = NtSecurity.AccessMaskToString(granted_access, enum_type, generic_mapping, false);
        GrantedGenericAccessString = NtSecurity.AccessMaskToString(granted_access, enum_type, generic_mapping, true);
        TokenId = token_info.TokenId.ToInt64();
        IsDirectory = is_directory;
        if (sd != null)
        {
            HasMandatoryLabel = sd.GetMandatoryLabel() != null;
            HasProcessTrustLabel = sd.ProcessTrustLabel != null;
        }
    }
}