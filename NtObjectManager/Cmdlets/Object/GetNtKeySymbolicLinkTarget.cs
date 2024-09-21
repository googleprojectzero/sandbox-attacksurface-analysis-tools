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
/// <para type="synopsis">Open and reads the symbolic link target for a key.</para>
/// <para type="description">This cmdlet opens a existing NT keys object and reads out the symbolic link target. 
/// The absolute path to the object in the NT object manager name space can be specified. 
/// It's also possible to open the object relative to an existing object by specified the -Root parameter.
/// To simplify calling it's also possible to specify the path in a Win32 format when using the -Win32Path parameter.</para>
/// </summary>
/// <example>
///   <code>Get-NtKeySymbolicLinkTarget -Path \Registry\Machine\SYSTEM\CurrentControlSet</code>
///   <para>Reads the CurrentControlSet symbolic link target.</para>
/// </example>
/// <example>
///   <code>Get-NtKeySymbolicLinkTarget -Win32Path HKLM\SYSTEM\CurrentControlSet</code>
///   <para>Reads the CurrentControlSet symbolic link target with a Win32 path.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "NtKeySymbolicLinkTarget")]
[OutputType(typeof(string))]
public class GetNtKeySymbolicLinkTarget : GetNtKeyCmdlet
{
    /// <summary>
    /// <para type="description">Specify to pass through the created key.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter FormatWin32Path { get; set; }

    /// <summary>
    /// Constructor.
    /// </summary>
    public GetNtKeySymbolicLinkTarget()
    {
        AttributeFlags |= AttributeFlags.OpenLink;
        Access = KeyAccessRights.QueryValue;
    }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        using NtKey key = (NtKey)base.CreateObject(obj_attributes);
        string target = key.GetSymbolicLinkTarget();
        return FormatWin32Path ? NtKeyUtils.NtKeyNameToWin32(target) : target;
    }
}
