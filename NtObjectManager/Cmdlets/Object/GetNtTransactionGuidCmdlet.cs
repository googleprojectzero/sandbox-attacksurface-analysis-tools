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
using NtCoreLib.Native.SafeHandles;
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;


/// <summary>
/// <para type="synopsis">Enumerates Kernel Transaction Manager object GUIDs.</para>
/// <para type="description">This cmdlet enumerates exiting Kernel Transaction Manager objects and returns the GUIDs associaed with the objects.</para>
/// </summary>
/// <example>
///   <code>$obj = Get-NtTransactionGuid -Type Transaction</code>
///   <para>Get all transaction object GUIDs.</para>
/// </example>
/// <example>
///   <code>$obj = Get-NtTransactionGuid -Type TransactionManager</code>
///   <para>Get all transaction manager object GUIDs.</para>
/// </example>
/// <example>
///   <code>$obj = Get-NtTransactionGuid -Type Transaction -TransactionManager $tm</code>
///   <para>Get all transaction object GUIDs from a transaction manager.</para>
/// </example>
/// <example>
///   <code>$obj = Get-NtTransactionGuid -Type ResourceManager -TransactionManager $tm</code>
///   <para>Get all resource manager object GUIDs from a transaction manager.</para>
/// </example>
/// <example>
///   <code>$obj = Get-NtTransactionGuid -Type Enlistment -ResourceManager $rm</code>
///   <para>Get all enlistment object GUIDs from a resource manager.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "NtTransactionGuid", DefaultParameterSetName = "Default")]
[OutputType(typeof(Guid))]
public class GetNtTransactionGuidCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify the object type for the enumeration.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0)]
    public KtmObjectType Type { get; set; }

    /// <summary>
    /// <para type="description">Specify the Resource Manager for the enumeration (needed for enlistments).</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "FromResourceManager")]
    public NtResourceManager ResourceManager { get; set; }

    /// <summary>
    /// <para type="description">Specify the Transaction Manager for the enumeration (needed for resource manager, optional for transactions).</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromTransactionManager")]
    public NtTransactionManager TransactionManager { get; set; }

    /// <summary>
    /// Process records.
    /// </summary>
    protected override void ProcessRecord()
    {
        NtObject enum_obj = null;

        switch (Type)
        {
            case KtmObjectType.Enlistment:
                if (ResourceManager == null)
                {
                    throw new ArgumentException("Must specify a Resource Manager for Enlistments");
                }
                enum_obj = ResourceManager;
                break;
            case KtmObjectType.ResourceManager:
                if (TransactionManager == null)
                {
                    throw new ArgumentException("Must specify a Transaction Manager for Resource Managers");
                }
                enum_obj = TransactionManager;
                break;
            case KtmObjectType.Transaction:
                enum_obj = TransactionManager;
                break;
            case KtmObjectType.TransactionManager:
                break;
            default:
                throw new ArgumentException("Invalid object type");
        }

        WriteObject(NtTransactionManagerUtils.EnumerateTransactionObjects(enum_obj?.Handle ?? SafeKernelObjectHandle.Null, Type), true);
    }
}
