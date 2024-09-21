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

using NtCoreLib.Win32.DirectoryService;
using NtCoreLib.Win32.Security.Authorization;

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// Access check result for an object type.
/// </summary>
public sealed class DsObjectTypeAccessCheckResult<T> where T : IDirectoryServiceObjectTree
{
    /// <summary>
    /// The object for the access check.
    /// </summary>
    public T Object { get; }

    /// <summary>
    /// The granted access.
    /// </summary>
    public DirectoryServiceAccessRights GrantedAccess { get; }

    /// <summary>
    /// Indicates if a specific access has been granted.
    /// </summary>
    /// <param name="access">The access to check.</param>
    /// <returns>True if access granted.</returns>
    public bool IsAccessGranted(DirectoryServiceAccessRights access)
    {
        return GrantedAccess.HasFlag(access);
    }

    /// <summary>
    /// Overridden ToString method.
    /// </summary>
    /// <returns>The name of the object.</returns>
    public override string ToString()
    {
        return Object.Name;
    }

    internal DsObjectTypeAccessCheckResult(T obj, AuthZAccessCheckResult result)
    {
        Object = obj;
        GrantedAccess = result.GrantedAccess.ToSpecificAccess<DirectoryServiceAccessRights>();
    }
}
