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
/// <para type="synopsis">Open a NT debug object by path.</para>
/// <para type="description">This cmdlet opens an existing NT debug object. The absolute path to the object in the NT object manager name space must be specified. 
/// It's also possible to create the object relative to an existing object by specified the -Root parameter.</para>
/// </summary>
/// <example>
///   <code>$obj = Get-NtDebug \BaseNamedObjects\ABC</code>
///   <para>Get a debug object with an absolute path.</para>
/// </example>
/// <example>
///   <code>$root = Get-NtDirectory \BaseNamedObjects&#x0A;$obj = Get-NtDebug ABC -Root $root</code>
///   <para>Get a debug object with a relative path.
///   </para>
/// </example>
/// <example>
///   <code>$obj = Get-NtDebug -Path \BaseNamedObjects\ABC&#x0A;$obj.Wait()</code>
///   <para>Get a debug object, wait for it to be set.</para>
/// </example>
/// <example>
///   <code>$obj = Get-NtDebug -Path \BaseNamedObjects\ABC&#x0A;$obj.Set()</code>
///   <para>Get a debug object, and set it.</para>
/// </example>
/// <example>
///   <code>cd NtObject:\BaseNamedObjects&#x0A;$obj = Get-NtDebug ABC</code>
///   <para>Get a debug object with a relative path based on the current location.
///   </para>
/// </example>
/// <example>
///   <code>Get-NtDebug -Current</code>
///   <para>Get the current debug object.
///   </para>
/// </example>
/// <example>
///   <code>Get-NtDebug -Process $p</code>
///   <para>Get the debug object from a process.
///   </para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.Get, "NtDebug")]
[OutputType(typeof(NtDebug))]
public sealed class GetNtDebugCmdlet : NtObjectBaseCmdletWithAccess<DebugAccessRights>
{
    /// <summary>
    /// Determine if the cmdlet can create objects.
    /// </summary>
    /// <returns>True if objects can be created.</returns>
    protected override bool CanCreateDirectories()
    {
        return false;
    }

    /// <summary>
    /// <para type="description">The NT object manager path to the object to use.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true, ParameterSetName = "FromPath")]
    public override string Path { get; set; }

    /// <summary>
    /// <para type="description">Open the current thread's debug object. Most parameters on this cmdlet will be ignored.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "FromCurrent")]
    public SwitchParameter Current { get; set; }

    /// <summary>
    /// <para type="description">Open the debug object from a process. Most parameters on this cmdlet will be ignored.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "FromProcess")]
    public NtProcess Process { get; set; }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        if (ParameterSetName == "FromPath")
        {
            return NtDebug.Open(obj_attributes, Access);
        }
        else if (ParameterSetName == "FromProcess")
        {
            return Process.OpenDebugObject();
        }
        else
        {
            return NtDebug.Current;
        }
    }
}
