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
/// <para type="synopsis">Creates a new NT transaction object.</para>
/// <para type="description">This cmdlet creates a new NT transaction object.</para>
/// </summary>
/// <example>
///   <code>$obj = New-NtTransaction \BaseNamedObjects\ABC</code>
///   <para>Create a transaction object with an absolute path.</para>
/// </example>
/// <example>
///   <code>$obj = New-NtTransaction \BaseNamedObjects\ABC -PreferredNode 2</code>
///   <para>Create a transaction object with an absolute path and preferred node 2.</para>
/// </example>
/// <example>
///   <code>$root = Get-NtDirectory \BaseNamedObjects&#x0A;$obj = New-NtTransaction ABC -Root $root</code>
///   <para>Create a transaction object with a relative path.
///   </para>
/// </example>
/// <example>
///   <code>cd NtObject:\BaseNamedObjects&#x0A;$obj = New-NtTransaction ABC</code>
///   <para>Create a transaction object with a relative path based on the current location.
///   </para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.New, "NtTransaction")]
[OutputType(typeof(NtTransaction))]
public sealed class NewNtTransactionCmdlet : NtObjectBaseCmdletWithAccess<TransactionAccessRights>
{
    /// <summary>
    /// <para type="description">Specify an optional Unit of Work GUID.</para>
    /// </summary>
    [Parameter]
    public Guid? UnitOfWork { get; set; }

    /// <summary>
    /// <para type="description">Specify an optional Transaction Manager.</para>
    /// </summary>
    [Parameter]
    public NtTransactionManager TransactionManager { get; set; }

    /// <summary>
    /// <para type="description">Specify flags for transaction creation.</para>
    /// </summary>
    [Parameter]
    public TransactionCreateFlags CreateFlags { get; set; }

    /// <summary>
    /// <para type="description">Specify an optional isolation level.</para>
    /// </summary>
    [Parameter]
    public int IsolationLevel { get; set; }

    /// <summary>
    /// <para type="description">Specify isolation falgs.</para>
    /// </summary>
    [Parameter]
    public TransactionIsolationFlags IsolationFlags { get; set; }

    /// <summary>
    /// <para type="description">Specify timeout in milliseconds (0 is Infinite).</para>
    /// </summary>
    [Parameter]
    public NtWaitTimeout Timeout { get; set; }

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
        return NtTransaction.Create(obj_attributes, Access, UnitOfWork, 
            TransactionManager, CreateFlags, IsolationLevel, 
            IsolationFlags, Timeout, Description);
    }
}
