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
///   <code>$obj = New-NtEnlistment -ResourceManager $rm -Transaction $t </code>
///   <para>Create an Enslitment with a Resource Manager and Transaction.</para>
/// </example>
/// <example>
///   <code>$obj = New-NtEnlistment -AutoGenerateGuid -TransactionManager $tm </code>
///   <para>Create a Resource Manager object with an auto-generated GUID.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.New, "NtEnlistment")]
[OutputType(typeof(NtEnlistment))]
public sealed class NewNtEnlistmentCmdlet : NtObjectBaseCmdletWithAccess<EnlistmentAccessRights>
{
    /// <summary>
    /// <para type="description">Specify the Resource Manager to contain the Enlistment.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0)]
    public NtResourceManager ResourceManager { get; set; }

    /// <summary>
    /// <para type="description">Specify the Transaction to associate with the Enlistment.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 1)]
    public NtTransaction Transaction { get; set; }

    /// <summary>
    /// <para type="description">Specify flags for Enlistment creation.</para>
    /// </summary>
    [Parameter]
    public EnlistmentCreateOptions CreateFlags { get; set; }

    /// <summary>
    /// <para type="description">Specify the notification mask for the Enlistment creation.</para>
    /// </summary>
    [Parameter]
    public TransactionNotificationMask NotificationMask { get; set; }

    /// <summary>
    /// <para type="description">Specify a key to associate with the Enlistment.</para>
    /// </summary>
    [Parameter]
    public IntPtr EnlistmentKey { get; set; }

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
        if (NotificationMask == 0)
        {
            NotificationMask = NtEnlistment.GetDefaultMaskForCreateOption(CreateFlags);
        }

        return NtEnlistment.Create(obj_attributes, Access, ResourceManager, Transaction, CreateFlags, NotificationMask, EnlistmentKey);
    }
}
