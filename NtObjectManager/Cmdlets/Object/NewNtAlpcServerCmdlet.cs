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
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Creates a new ALPC server by path.</para>
/// <para type="description">This cmdlet creates a new NT ALPC server. The absolute path to the object in the NT object manager name space must be specified.
/// </para>
/// </summary>
/// <example>
///   <code>$obj = New-NtAlpcServer "\RPC Control\ABC"</code>
///   <para>Create a new ALPC server with an absolute path.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.New, "NtAlpcServer")]
[OutputType(typeof(NtAlpcServer))]
public class NewNtAlpcServerCmdlet : NtObjectBaseCmdlet
{
    /// <summary>
    /// Determine if the cmdlet can create objects.
    /// </summary>
    /// <returns>True if objects can be created.</returns>
    protected override bool CanCreateDirectories()
    {
        return true;
    }

    /// <summary>
    /// <para type="description">The NT object manager path to the object to use.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public override string Path { get; set; }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        return NtAlpcServer.Create(obj_attributes, PortAttributes);
    }

    /// <summary>
    /// <para type="description">Optional port attributes.</para>
    /// </summary>
    [Parameter]
    public AlpcPortAttributes PortAttributes { get; set; }
}
