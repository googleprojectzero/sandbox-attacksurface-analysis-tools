//  Copyright 2016 Google Inc. All Rights Reserved.
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
/// <para type="synopsis">Unloads a registry hive.</para>
/// <para type="description">This cmdlet unloads a registry hive in the registry namespace.</para>
/// </summary>
/// <example>
///   <code>Remove-NtKeyHive \Registry\Machine\ABC</code>
///   <para>Unload the \Registry\Machine\ABC hive.</para>
/// </example>
/// <example>
///   <code>Remove-NtKey \Registry\Machine\ABC -Flags ForceUnload</code>
///   <para>Unload the \Registry\Machine\ABC hive, forcing the unload if necessary.</para>
/// </example>
[Cmdlet(VerbsCommon.Remove, "NtKeyHive")]
public sealed class RemoveKeyHiveCmdlet : NtObjectBaseCmdlet
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
    [Parameter(Position = 0, Mandatory = true)]
    public override string Path { get; set; }

    /// <summary>
    /// Virtual method to return the value of the Path variable.
    /// </summary>
    /// <returns>The object path.</returns>
    protected override string ResolvePath()
    {
        if (Win32Path)
        {
            return NtKeyUtils.Win32KeyNameToNt(Path);
        }
        else
        {
            return Path;
        }
    }

    /// <summary>
    /// <para type="description">Specifes the flags for unloading the hive.</para>
    /// </summary>
    [Parameter]
    public UnloadKeyFlags Flags { get; set; }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>Always null.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        NtKey.UnloadKey(obj_attributes, Flags, true);
        return null;
    }
}
