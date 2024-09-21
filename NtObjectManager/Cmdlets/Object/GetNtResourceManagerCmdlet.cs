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
/// <para type="synopsis">Open a NT Resource Manager object or all from a Transaction Manager..</para>
/// <para type="description">This cmdlet opens an existing NT Resource Manager object.</para>
/// </summary>
/// <example>
///   <code>$obj = Get-NtTransaction -TransactionManager $tm</code>
///   <para>Get all Resource Manager objects from a Transaction Manager.</para>
/// </example>
/// <example>
///   <code>$obj = Get-NtTransaction -ResourceManagerGuid '04422e91-63c2-4025-944d-d66fae133274' -TransactionManager $tm</code>
///   <para>Get a Resource Manager object from its GUID and Transaction Manager.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.Get, "NtResourceManager", DefaultParameterSetName = "All")]
[OutputType(typeof(NtResourceManager))]
public class GetNtResourceManagerCmdlet : NtObjectBaseNoPathCmdletWithAccess<ResourceManagerAccessRights>
{
    /// <summary>
    /// <para type="description">Specify the Resource Manager GUID to open.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromId")]
    [Alias("rmguid")]
    public Guid ResourceManagerGuid { get; set; }

    /// <summary>
    /// <para type="description">Specify the Transaction Manager containing the Resource Manager.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 1, ParameterSetName = "FromId"), 
        Parameter(Mandatory = true, Position = 0, ParameterSetName = "All")]
    public NtTransactionManager TransactionManager { get; set; }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        if (ParameterSetName == "All")
        {
            return TransactionManager.GetAccessibleResourceManager(obj_attributes, Access);
        }
        return NtResourceManager.Open(obj_attributes, Access, TransactionManager, ResourceManagerGuid);
    }
}
