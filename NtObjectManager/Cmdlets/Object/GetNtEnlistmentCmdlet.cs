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
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Open a NT Enlistment object or all from a Resource Manager.</para>
/// <para type="description">This cmdlet opens an existing NT Enlistment object or all from a Resource Manager.</para>
/// </summary>
/// <example>
///   <code>$obj = Get-NtEnlistment -ResourceManager $rm</code>
///   <para>Get all Enlistment objects from a Resource Manager.</para>
/// </example>
/// <example>
///   <code>$obj = Get-NtEnlistment -EnlistmentGuid '04422e91-63c2-4025-944d-d66fae133274' -ResourceManager $rm</code>
///   <para>Get a Enlistment object from its GUID and Resource Manager.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.Get, "NtEnlistment", DefaultParameterSetName = "All")]
[OutputType(typeof(NtEnlistment))]
public class GetNtEnlistmentCmdlet : NtObjectBaseNoPathCmdletWithAccess<EnlistmentAccessRights>
{
    /// <summary>
    /// <para type="description">Specify the Enlistment GUID to open.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromId")]
    public Guid EnlistmentGuid { get; set; }

    /// <summary>
    /// <para type="description">Specify the Transaction Manager containing the Resource Manager.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 1, ParameterSetName = "FromId"),
        Parameter(Mandatory = true, Position = 0, ParameterSetName = "All")]
    public NtResourceManager ResourceManager { get; set; }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        if (ParameterSetName == "All")
        {
            return ResourceManager.GetAccessibleEnlistment(obj_attributes, Access);
        }
        return NtEnlistment.Open(obj_attributes, Access, ResourceManager, EnlistmentGuid);
    }
}
