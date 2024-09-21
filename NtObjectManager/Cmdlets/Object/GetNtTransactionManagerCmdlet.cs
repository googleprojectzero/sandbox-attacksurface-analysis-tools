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
/// <para type="synopsis">Open a NT transaction manager object or all transaction manager objects.</para>
/// <para type="description">This cmdlet opens an existing NT transaction manager object or all transaction manager objects.</para>
/// </summary>
/// <example>
///   <code>$obj = Get-NtTransactionManager</code>
///   <para>Get all accessible transaction manager objects.</para>
/// </example>
/// <example>
///   <code>$obj = Get-NtTransactionManager \BaseNamedObjects\ABC</code>
///   <para>Get a transaction manager object with an absolute path.</para>
/// </example>
/// <example>
///   <code>$obj = Get-NtTransactionManager -Identity '04422e91-63c2-4025-944d-d66fae133274'</code>
///   <para>Get a transaction manager object from its identity GUID.</para>
/// </example>
/// <example>
///   <code>$obj = Get-NtTransactionManager \??\c:\abc\xyz</code>
///   <para>Get a transaction manager object from an existing logfile.</para>
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
[Cmdlet(VerbsCommon.Get, "NtTransactionManager", DefaultParameterSetName = "All")]
[OutputType(typeof(NtTransactionManager))]
public class GetNtTransactionManagerCmdlet : NtObjectBaseCmdletWithAccess<TransactionManagerAccessRights>
{
    /// <summary>
    /// <para type="description">The NT object manager path to the object to use.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromPath"), Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromLogFile")]
    public override string Path { get; set; }

    /// <summary>
    /// <para type="description">Specify a identity GUID to open.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "FromId")]
    public Guid Identity { get; set; }

    /// <summary>
    /// <para type="description">Specify optional open flags..</para>
    /// </summary>
    [Parameter]
    public TransactionManagerOpenOptions OpenFlags { get; set; }

    /// <summary>
    /// <para type="description">Specify that the path resolves to a logfile rather than an object manager path.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "FromLogFile")]
    public SwitchParameter LogFile { get; set; }

    /// <summary>
    /// Determine if the cmdlet can create objects.
    /// </summary>
    /// <returns>True if objects can be created.</returns>
    protected override bool CanCreateDirectories()
    {
        return false;
    }

    /// <summary>
    /// Virtual method to resolve the value of the Path variable.
    /// </summary>
    /// <returns>The object path, returns null if resolving a log file.</returns>
    protected override string ResolvePath()
    {
        if (ParameterSetName == "FromLogFile")
        {
            if (Root != null)
            {
                throw new ArgumentException("Can't specify a root object when resolving from a log file");
            }
            return null;
        }
        return base.ResolvePath();
    }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        Guid? identity = null;
        string logfile = null;
        switch (ParameterSetName)
        {
            case "All":
                return NtTransactionManager.GetAccessibleTransactionManager(obj_attributes, Access, OpenFlags);
            case "FromLogFile":
                logfile = base.ResolvePath();
                break;
            case "FromId":
                identity = Identity;
                break;
        }
        return NtTransactionManager.Open(obj_attributes, Access, 
            logfile, identity, OpenFlags);
    }
}
