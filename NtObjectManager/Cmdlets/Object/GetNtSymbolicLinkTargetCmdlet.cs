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

using NtCoreLib;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Get the target path for an existing NT symbolic link object.</para>
/// <para type="description">This cmdlet opens a existing NT symbolic link object and queries its target path. That can be done using Get-NtSymbolicLink and the Query method but
/// this simplifies the operation so that the object handle doesn't have to be closed.</para>
/// </summary>
/// <example>
///   <code>Get-NtSymbolicLinkTarget \DosDevices\ABC</code>
///   <para>Gets the symbolic link object target with an absolute path.</para>
/// </example>
/// <example>
///   <code>$root = Get-NtDirectory \DosDevices&#x0A;Get-NtSymbolicLinkTarget ABC -Root $root</code>
///   <para>Gets the symbolic link object target with a relative path.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.Get, "NtSymbolicLinkTarget")]
public class GetNtSymbolicLinkTargetCmdlet : NtObjectBaseCmdlet
{
    /// <summary>
    /// Determine if the cmdlet can create objects.
    /// </summary>
    /// <returns>True if objects can be created.</returns>
    protected override bool CanCreateDirectories()
    {
        return false;
    }

    /// <summary>
    /// <para type="description">The NT object manager path to the object to use.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public override string Path { get; set; }

    /// <summary>
    /// <para type="description">Resolve the final target. This will follow the target if it's still a symbolic link.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter Resolve { get; set; }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        using NtSymbolicLink link = NtSymbolicLink.Open(obj_attributes, SymbolicLinkAccessRights.Query);
        if (Resolve)
            return NtSymbolicLink.ResolveTarget(link.Target);
        return link.Target;
    }
}

