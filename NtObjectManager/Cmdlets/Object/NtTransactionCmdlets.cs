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

using NtApiDotNet;
using System;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object
{
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
}
