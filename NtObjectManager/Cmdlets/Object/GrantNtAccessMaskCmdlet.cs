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

using NtCoreLib;
using NtCoreLib.Security.Authorization;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Grants specific bits on an access mask and returns the updated access mask.</para>
/// <para type="description">This cmdlet grants specific bits on an access mask and returns the updated access mask</para>
/// </summary>
/// <example>
///   <code>$access = Grant-NtAccessMask $access WriteDac</code>
///   <para>Adds WriteDac to the access.</para>
/// </example>
[Cmdlet(VerbsSecurity.Grant, "NtAccessMask", DefaultParameterSetName = "SetAccess")]
public class GrantNtAccessMaskCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">The initial access mask to update.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public AccessMask AccessMask { get; set; }

    /// <summary>
    /// <para type="description">The access mask to grant.</para>
    /// </summary>
    [Parameter(Position = 1, Mandatory = true, ParameterSetName = "SetAccess")]
    public GenericAccessRights SetAccess { get; set; }

    /// <summary>
    /// <para type="description">The raw access mask to grant.</para>
    /// </summary>
    [Parameter(Position = 1, Mandatory = true, ParameterSetName = "RawSetAccess")]
    public AccessMask RawSetAccess { get; set; }

    private AccessMask GetAccessMask()
    {
        if (ParameterSetName == "RawSetAccess")
        {
            return RawSetAccess;
        }
        return SetAccess;
    }

    /// <summary>
    /// Process record.
    /// </summary>
    protected override void ProcessRecord()
    {
        WriteObject(AccessMask | GetAccessMask());
    }
}
