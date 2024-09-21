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
/// <para type="synopsis">Open and sets the symbolic link target for a key.</para>
/// <para type="description">This cmdlet opens a existing NT key object and sets out the symbolic link target. 
/// The absolute path to the object in the NT object manager name space can be specified. 
/// It's also possible to open the object relative to an existing object by specified the -Root parameter.
/// To simplify calling it's also possible to specify the path in a Win32 format when using the -Win32Path parameter.</para>
/// </summary>
/// <example>
///   <code>Set-NtKeySymbolicLinkTarget -Path \Registry\Machine\SYSTEM\CurrentControlSet -Target \Registry\Machine\ABC</code>
///   <para>Sets the CurrentControlSet symbolic link target.</para>
/// </example>
[Cmdlet(VerbsCommon.Set, "NtKeySymbolicLinkTarget")]
public class SetNtKeySymbolicLinkTarget : GetNtKeyCmdlet
{
    /// <summary>
    /// Constructor.
    /// </summary>
    public SetNtKeySymbolicLinkTarget()
    {
        AttributeFlags |= AttributeFlags.OpenLink;
        Access = KeyAccessRights.SetValue;
    }

    /// <summary>
    /// <para type="description">Specify a target for the symbolic link.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 1)]
    public string Target { get; set; }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        using NtKey key = (NtKey)base.CreateObject(obj_attributes);
        key.SetSymbolicLinkTarget(Win32Path ? NtKeyUtils.Win32KeyNameToNt(Target) : Target);
        return null;
    }
}
