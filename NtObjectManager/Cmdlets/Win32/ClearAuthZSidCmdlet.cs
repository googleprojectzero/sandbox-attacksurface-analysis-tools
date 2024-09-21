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

using NtCoreLib.Security.Token;
using NtCoreLib.Win32.Security.Authorization;
using System;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Win32;

/// <summary>
/// <para type="synopsis">Removes all SIDs from the AuthZ context..</para>
/// <para type="description">This cmdlet allows you to remove all SIDs from an AuthZ context. You can specify
/// normal, restricted or device SIDs.</para>
/// </summary>
/// <example>
///   <code>Clear-AuthZSid $ctx</code>
///   <para>Removes all normal SIDs in the context.</para>
/// </example>
/// <example>
///   <code>Clear-AuthZSid $ctx -SidType Restricted</code>
///   <para>Removes all restricted SIDs in the context.</para>
/// </example>
[Cmdlet(VerbsCommon.Clear, "AuthZSid")]
public class ClearAuthZSidCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify the AuthZ client context.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0)]
    public AuthZContext Context { get; set; }

    /// <summary>
    /// <para type="description">Specify the the type of SIDs to remove.</para>
    /// </summary>
    [Parameter(Position = 1)]
    public AuthZGroupSidType SidType { get; set; }

    /// <summary>
    /// Constructor.
    /// </summary>
    public ClearAuthZSidCmdlet()
    {
        SidType = AuthZGroupSidType.Normal;
    }

    private UserGroup[] GetSids()
    {
        switch (SidType)
        {
            case AuthZGroupSidType.Normal:
                return Context.Groups;
            case AuthZGroupSidType.Device:
                return Context.DeviceGroups;
            case AuthZGroupSidType.Capability:
                return Context.Capabilities;
            case AuthZGroupSidType.Restricted:
                return Context.RestrictedSids;
            default:
                throw new ArgumentException("Invalid SID type.");
        }
    }

    /// <summary>
    /// Process record.
    /// </summary>
    protected override void ProcessRecord()
    {
        Context.ModifyGroups(SidType, GetSids().Select(g => g.Sid), AuthZSidOperation.Delete);
    }
}
