﻿//  Copyright 2016 Google Inc. All Rights Reserved.
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
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Create a new NT mailslot file object.</para>
/// <para type="description">This cmdlet creates a new NT mailslot file object. The absolute path to the object in the NT object manager name space can be specified. 
/// It's also possible to open the object relative to an existing object by specified the -Root parameter.</para>
/// </summary>
/// <example>
///   <code>$obj = New-NtMailslotFile \??\mailslot\abc</code>
///   <para>Creates a new file mailslot object with an absolute path.</para>
/// </example>
/// <example>
///   <code>$obj = New-NtMailslotFile \\.\mailslot\abc -Win32Path</code>
///   <para>Creates a new file mailslot object with an absolute win32 path.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.New, "NtMailslotFile")]
[OutputType(typeof(NtMailslotFile))]
public class NewNtMailslotFileCmdlet : GetNtFileCmdlet
{
    /// <summary>
    /// <para type="description">Specify the default timeout for the mailslot in MS (-1 for no timeout)</para>
    /// </summary>
    [Parameter]
    public int DefaultTimeoutMs { get; set; }
    
    /// <summary>
    /// <para type="description">Specify the maximum message size (0 means any size)</para>
    /// </summary>
    [Parameter]
    public int MaximumMessageSize { get; set; }

    /// <summary>
    /// <para type="description">Specify the mailslot quota.</para>
    /// </summary>
    [Parameter]
    public int MailslotQuota { get; set; }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        return NtFile.CreateMailslot(obj_attributes, Access, Options, 
            MaximumMessageSize, MailslotQuota, DefaultTimeoutMs);
    }

    /// <summary>
    /// Constructor
    /// </summary>
    public NewNtMailslotFileCmdlet()
    {
        DefaultTimeoutMs = -1;
        Access = FileAccessRights.GenericRead | FileAccessRights.ReadAttributes | FileAccessRights.WriteDac;
    }
}
