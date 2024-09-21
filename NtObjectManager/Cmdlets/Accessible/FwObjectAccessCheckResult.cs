//  Copyright 2021 Google LLC. All Rights Reserved.
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

using NtCoreLib.Net.Firewall;
using NtCoreLib.Security.Authorization;
using System;

namespace NtObjectManager.Cmdlets.Accessible;

/// <summary>
/// <para type="description">Access check result for a firewall object.</para>
/// </summary>
public class FwObjectAccessCheckResult : CommonAccessCheckResult
{
    /// <summary>
    /// Firewall object description.
    /// </summary>
    public string Description { get; }

    /// <summary>
    /// Firewall object key.
    /// </summary>
    public Guid Key { get; }

    /// <summary>
    /// Firewall object key name.
    /// </summary>
    public string KeyName { get; }

    internal FwObjectAccessCheckResult(string name, string description, Guid key, string key_name, FwObjectType fw_type, AccessMask granted_access, 
        GenericMapping generic_mapping, SecurityDescriptor sd, bool is_directory, TokenInformation token_info) 
        : base(name, fw_type.ToString(), granted_access, generic_mapping, sd, typeof(FirewallAccessRights), is_directory, token_info)
    {
        Description = description;
        Key = key;
        KeyName = key_name;
    }
}
