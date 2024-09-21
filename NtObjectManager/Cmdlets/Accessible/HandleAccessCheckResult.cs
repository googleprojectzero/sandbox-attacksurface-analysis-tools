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
using NtCoreLib.Security.Authorization;
using System;

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// <para type="description">Access check result for a handle.</para>
/// </summary>
public class HandleAccessCheckResult : CommonAccessCheckResult
{
    /// <summary>
    /// Specifies the maximum access that can be accessed if the resource was reopened.
    /// </summary>
    public AccessMask? MaximumAccess { get; }

    /// <summary>
    /// Specifies whether the access granted in the handle is different than would
    /// be granted if the resource was reopened.
    /// </summary>
    public bool DifferentAccess { get; }

    /// <summary>
    /// Process ID containing the handle.
    /// </summary>
    public int ProcessId { get; }

    /// <summary>
    /// The handle value.
    /// </summary>
    public int Handle { get; }

    /// <summary>
    /// The object address.
    /// </summary>
    public ulong Object { get; }

    internal HandleAccessCheckResult(MaximumAccess maximum_access, NtHandle handle, string name, string type_name, AccessMask granted_access,
        GenericMapping generic_mapping, string sddl, Type enum_type, bool is_directory, TokenInformation token_info) 
        : base(name, type_name, granted_access, generic_mapping, 
              !string.IsNullOrWhiteSpace(sddl) ? new SecurityDescriptor(sddl) : null, 
              enum_type, is_directory, token_info)
    {
        if (maximum_access != null)
        {
            MaximumAccess = maximum_access.Access;
            DifferentAccess = (granted_access & MaximumAccess) != granted_access;
        }
        ProcessId = handle.ProcessId;
        Handle = handle.Handle;
        Object = handle.Object;
    }
}
