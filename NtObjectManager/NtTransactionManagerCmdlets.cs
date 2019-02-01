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
using System.Management.Automation;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="synopsis">Open a NT transaction manager object.</para>
    /// <para type="description">This cmdlet opens an existing NT transaction manager object.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = Get-NtTransactionManager \BaseNamedObjects\ABC</code>
    ///   <para>Get a transaction manager object with an absolute path.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtTransactionManager -Identity '04422e91-63c2-4025-944d-d66fae133274'</code>
    ///   <para>Get a transaction manager object from its identity GUID.</para>
    /// </example>
    /// <example>
    ///   <code>$root = Get-NtDirectory \BaseNamedObjects&#x0A;$obj = Get-NtTransactionManager ABC -Root $root</code>
    ///   <para>Get a transaction manager object with a relative path.
    ///   </para>
    /// </example>
    /// <example>
    ///   <code>cd NtObject:\BaseNamedObjects&#x0A;$obj = Get-NtTransactionManager ABC</code>
    ///   <para>Get a transaction manager object with a relative path based on the current location.
    ///   </para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Get, "NtTransactionManager")]
    [OutputType(typeof(NtTransaction))]
    public class GetNtTransactionManagerCmdlet : NtObjectBaseCmdletWithAccess<TransactionManagerAccessRights>
    {
        /// <summary>
        /// <para type="description">The NT object manager path to the object to use.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromPath")]
        public override string Path { get; set; }

        /// <summary>
        /// <para type="description">Specify a identity GUID to open.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromPath"), Parameter(ParameterSetName = "FromId")]
        public Guid? Identity { get; set; }

        /// <summary>
        /// <para type="description">Specify optional open flags..</para>
        /// </summary>
        [Parameter]
        public TransactionManagerOpenOptions OpenFlags { get; set; }

        /// <summary>
        /// <para type="description">Specify an optional log file name.</para>
        /// </summary>
        [Parameter]
        public string LogFileName { get; set; }

        /// <summary>
        /// Determine if the cmdlet can create objects.
        /// </summary>
        /// <returns>True if objects can be created.</returns>
        protected override bool CanCreateDirectories()
        {
            return false;
        }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtTransactionManager.Open(obj_attributes, Access, 
                LogFileName, Identity, OpenFlags);
        }
    }

    /// <summary>
    /// <para type="synopsis">Creates a new NT transaction manager object.</para>
    /// <para type="description">This cmdlet creates a new NT transaction object.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = New-NtTransaction \BaseNamedObjects\ABC</code>
    ///   <para>Create a transaction manager object with an absolute path.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = New-NtTransaction \BaseNamedObjects\ABC -PreferredNode 2</code>
    ///   <para>Create a  transaction manager object with an absolute path and preferred node 2.</para>
    /// </example>
    /// <example>
    ///   <code>$root = Get-NtDirectory \BaseNamedObjects&#x0A;$obj = New-NtTransaction ABC -Root $root</code>
    ///   <para>Create a  transaction manager object with a relative path.
    ///   </para>
    /// </example>
    /// <example>
    ///   <code>cd NtObject:\BaseNamedObjects&#x0A;$obj = New-NtTransaction ABC</code>
    ///   <para>Create a  transaction manager object with a relative path based on the current location.
    ///   </para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.New, "NtTransactionManager")]
    [OutputType(typeof(NtPartition))]
    public sealed class NewNtTransactionManagerCmdlet : NtObjectBaseCmdletWithAccess<TransactionManagerAccessRights>
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        public NewNtTransactionManagerCmdlet()
        {
            CreateFlags = TransactionManagerCreateOptions.Volatile;
        }

        /// <summary>
        /// <para type="description">Specify flags for transaction manager creation.</para>
        /// </summary>
        [Parameter]
        public TransactionManagerCreateOptions CreateFlags { get; set; }

        /// <summary>
        /// <para type="description">Specify an optional commit strength.</para>
        /// </summary>
        [Parameter]
        public int CommitStrength { get; set; }

        /// <summary>
        /// <para type="description">Specify an optional log file name.</para>
        /// </summary>
        [Parameter]
        public string LogFileName { get; set; }

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
            return NtTransactionManager.Create(obj_attributes, Access, 
                LogFileName, CreateFlags, CommitStrength);
        }
    }
}
