//  Copyright 2020 Google Inc. All Rights Reserved.
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
/// <para type="synopsis">Create a new NT key symbolic link.</para>
/// <para type="description">This cmdlet creates a new NT key symbolic link. The absolute path to the object in the NT object manager name space must be specified. 
/// It's also possible to create the object relative to an existing object by specified the -Root parameter. Unlike New-NtKey this will only return the created
/// Key if PassThru is specified.</para>
/// </summary>
/// <example>
///   <code>New-NtKeySymbolicLink \Registry\Machine\Software\ABC -Target \Registry\Machine\Sofware\XYZ</code>
///   <para>Create a new key symbolic link object with an absolute path.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.New, "NtKeySymbolicLink")]
[OutputType(typeof(NtKey))]
public class NewNtKeySymbolicLink : GetNtKeyCmdlet
{
    /// <summary>
    /// <para type="description">Specify a target for the symbolic link.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 1)]
    public string Target { get; set; }

    /// <summary>
    /// <para type="description">Specify to pass through the created key.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter PassThru { get; set; }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        using var key = NtKey.Create(obj_attributes, Access, Options | KeyCreateOptions.CreateLink, Transaction);
        key.SetSymbolicLinkTarget(Win32Path ? NtKeyUtils.Win32KeyNameToNt(Target) : Target);
        if (PassThru)
        {
            return key.Duplicate();
        }
        return null;
    }
}
