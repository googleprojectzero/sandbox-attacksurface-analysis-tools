//  Copyright 2019 Google Inc. All Rights Reserved.
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
/// <para type="synopsis">Creates a new NT partition object.</para>
/// <para type="description">This cmdlet creates a new NT partition object.</para>
/// </summary>
/// <example>
///   <code>$obj = New-NtPartition \BaseNamedObjects\ABC</code>
///   <para>Create a partition object with an absolute path.</para>
/// </example>
/// <example>
///   <code>$obj = New-NtPartition \BaseNamedObjects\ABC -PreferredNode 2</code>
///   <para>Create a partition object with an absolute path and preferred node 2.</para>
/// </example>
/// <example>
///   <code>$root = Get-NtDirectory \BaseNamedObjects&#x0A;$obj = New-NtPartition ABC -Root $root</code>
///   <para>Create a partition object with a relative path.
///   </para>
/// </example>
/// <example>
///   <code>cd NtObject:\BaseNamedObjects&#x0A;$obj = New-NtPartition ABC</code>
///   <para>Create a partition object with a relative path based on the current location.
///   </para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.New, "NtPartition")]
[OutputType(typeof(NtPartition))]
public sealed class NewNtPartitionCmdlet : NtObjectBaseCmdletWithAccess<MemoryPartitionAccessRights>
{
    /// <summary>
    /// Constructor.
    /// </summary>
    public NewNtPartitionCmdlet() 
    {
        PreferredNode = -1;
    }

    /// <summary>
    /// Determine if the cmdlet can create objects.
    /// </summary>
    /// <returns>True if objects can be created.</returns>
    protected override bool CanCreateDirectories()
    {
        return true;
    }

    /// <summary>
    /// <para type="description">Specifies the preferred NUMA node, -1 means ideal node.</para>
    /// </summary>
    [Parameter]
    public int PreferredNode { get; set; }

    /// <summary>
    /// <para type="description">Specifies the parent partition. Not specifying means use the system partition.</para>
    /// </summary>
    [Parameter]
    public NtPartition ParentPartition { get; set; }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        return NtPartition.Create(obj_attributes, Access, ParentPartition, PreferredNode);
    }
}
