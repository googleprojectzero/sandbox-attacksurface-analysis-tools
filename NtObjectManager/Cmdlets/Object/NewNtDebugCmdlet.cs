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
/// <para type="synopsis">Create a new NT debug object.</para>
/// <para type="description">This cmdlet creates a new NT debug object. The absolute path to the object in the NT object manager name space can be specified. 
/// It's also possible to create the object relative to an existing object by specified the -Root parameter. If no path is specified than an unnamed object will be created which
/// can only be duplicated by handle. You can also attach a process to the new debug object immediately after creation.</para>
/// </summary>
/// <example>
///   <code>$obj = New-NtDebug</code>
///   <para>Create a new anonymous debug object.</para>
/// </example>
/// <example>
///   <code>$obj = New-NtDebug \BaseNamedObjects\ABC</code>
///   <para>Create a new debug object with an absolute path.</para>
/// </example>
/// <example>
///   <code>$root = Get-NtDirectory \BaseNamedObjects&#x0A;$obj = New-NtDebug ABC -Root $root</code>
///   <para>Create a new debug object with a relative path.
///   </para>
/// </example>
/// <example>
///   <code>cd NtObject:\BaseNamedObjects&#x0A;$obj = New-NtDebug ABC</code>
///   <para>Create a new debug object with a relative path based on the current location.
///   </para>
/// </example>
/// <example>
///   <code>$obj = New-NtDebug -ProcessId 12345</code>
///   <para>Create a new anonymous debug object and attach to PID 12345.</para>
/// </example>
/// <example>
///   <code>$obj = New-NtDebug -Process $proc</code>
///   <para>Create a new anonymous debug object and attach to a process object.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.New, "NtDebug", DefaultParameterSetName = "NoAttach")]
[OutputType(typeof(NtDebug))]
public sealed class NewNtDebugCmdlet : NtObjectBaseCmdletWithAccess<DebugAccessRights>
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
    /// <para type="description">Specify a process ID to attach to after creation.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "AttachPid")]
    [Alias("pid")]
    public int ProcessId { get; set; }

    /// <summary>
    /// <para type="description">Specify a process to attach to after creation.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "AttachProcess")]
    public NtProcess Process { get; set; }

    /// <summary>
    /// <para type="description">Specify flags for create.</para>
    /// </summary>
    [Parameter]
    public DebugObjectFlags Flags { get; set; }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        using var obj = NtDebug.Create(obj_attributes, Access, Flags);
        switch (ParameterSetName)
        {
            case "AttachPid":
                obj.Attach(ProcessId);
                break;
            case "AttachProcess":
                obj.Attach(Process);
                break;
        }
        return obj.Duplicate();
    }
}
