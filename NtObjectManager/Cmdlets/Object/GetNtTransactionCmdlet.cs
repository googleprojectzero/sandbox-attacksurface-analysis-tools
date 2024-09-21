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
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Open a NT transaction object or get all accessible transaction objects.</para>
/// <para type="description">This cmdlet opens an existing NT transaction object or can get all accessible transaction objects.</para>
/// </summary>
/// <example>
///   <code>$obj = Get-NtTransaction</code>
///   <para>Get all accessible transaction objects.</para>
/// </example>
/// <example>
///   <code>$obj = Get-NtTransaction -TransactionManager $tm</code>
///   <para>Get all accessible transaction objects in a specific transaction manager.</para>
/// </example>
/// <example>
///   <code>$obj = Get-NtTransaction -UnitOfWork '04422e91-63c2-4025-944d-d66fae133274'</code>
///   <para>Get a transaction object from its Unit of Work GUID.</para>
/// </example>
/// <example>
///   <code>$obj = Get-NtTransaction -UnitOfWork '04422e91-63c2-4025-944d-d66fae133274' -TransactionManager $tm</code>
///   <para>Get a transaction object from its Unit of Work GUID from a specific transaction manager.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.Get, "NtTransaction", DefaultParameterSetName = "All")]
[OutputType(typeof(NtTransaction))]
public class GetNtTransactionCmdlet : NtObjectBaseNoPathCmdletWithAccess<TransactionAccessRights>
{
    /// <summary>
    /// <para type="description">Specify the Unit of Work GUID to open.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "FromId", Position = 0)]
    public Guid UnitOfWork { get; set; }

    /// <summary>
    /// <para type="description">Specify an optional Transaction Manager.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromId", Position = 1), Parameter(ParameterSetName = "All")]
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
            return NtTransaction.GetAccessibleTransaction(obj_attributes, Access, TransactionManager).ToArray();
        }
        return NtTransaction.Open(obj_attributes, Access, UnitOfWork, TransactionManager);
    }
}
