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
/// <para type="synopsis">Creates a new NT Resource Manager object.</para>
/// <para type="description">This cmdlet creates a new NT Resource Manager object.</para>
/// </summary>
/// <example>
///   <code>$obj = New-NtResourceManager -TransactionManager $tm </code>
///   <para>Create a Resource Manager object with an auto-generated GUID.</para>
/// </example>
/// <example>
///   <code>$obj = New-NtResourceManager -ResourceManagerGuid '04422e91-63c2-4025-944d-d66fae133274' -TransactionManager $tm </code>
///   <para>Create a Resource Manager object with a specified GUID.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.New, "NtResourceManager", DefaultParameterSetName = "FromGuid")]
[OutputType(typeof(NtResourceManager))]
public sealed class NewNtResourceManagerCmdlet : NtObjectBaseCmdletWithAccess<ResourceManagerAccessRights>
{
    /// <summary>
    /// Constructor.
    /// </summary>
    public NewNtResourceManagerCmdlet()
    {
        ResourceManagerGuid = Guid.NewGuid();
    }

    /// <summary>
    /// <para type="description">Specify the Resource Manager GUID to create.</para>
    /// </summary>
    [Parameter]
    [Alias("rmguid")]
    public Guid ResourceManagerGuid { get; set; }

    /// <summary>
    /// <para type="description">Specify the Transaction Manager to contain the Resource Manager.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0)]
    public NtTransactionManager TransactionManager { get; set; }

    /// <summary>
    /// <para type="description">Specify flags for resource manager creation.</para>
    /// </summary>
    [Parameter]
    public ResourceManagerCreateOptions CreateFlags { get; set; }

    /// <summary>
    /// <para type="description">Specify an optional description.</para>
    /// </summary>
    [Parameter]
    public string Description { get; set; }

    /// <summary>
    /// Determine if the cmdlet can create objects.
    /// </summary>
    /// <returns>True if objects can be created.</returns>
    protected override bool CanCreateDirectories()
    {
        return true;
    }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        if (TransactionManager.Volatile)
        {
            CreateFlags |= ResourceManagerCreateOptions.Volatile;
        }

        return NtResourceManager.Create(obj_attributes, Access, 
            TransactionManager, ResourceManagerGuid,
            CreateFlags, Description);
    }
}
