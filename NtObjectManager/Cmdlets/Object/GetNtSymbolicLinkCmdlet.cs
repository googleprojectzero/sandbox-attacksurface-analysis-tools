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
/// <para type="synopsis">Open a existing NT symbolic link object.</para>
/// <para type="description">This cmdlet opens a existing NT symbolic link object. The absolute path to the object in the NT object manager name space can be specified. 
/// It's also possible to open the object relative to an existing object by specified the -Root parameter.</para>
/// </summary>
/// <example>
///   <code>$obj = Get-NtSymbolicLink \DosDevices\ABC</code>
///   <para>Open a symbolic link object with an absolute path.</para>
/// </example>
/// <example>
///   <code>$root = Get-NtDirectory \DosDevices&#x0A;$obj = Get-NtSymbolicLink ABC -Root $root</code>
///   <para>Open a symbolic link object with a relative path.</para>
/// </example>
/// <example>
///   <code>cd NtObject:\BaseNamedObjects&#x0A;$obj = Get-NtSymbolicLink ABC</code>
///   <para>Get a symbolic link object with a relative path based on the current location.</para>
/// </example>
/// <example>
///   <code>$obj = Get-NtSymbolicLink \DosDevices\ABC&#x0A;$obj.Query()</code>
///   <para>Open a symbolic link object and query its target.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.Get, "NtSymbolicLink")]
public class GetNtSymbolicLinkCmdlet : NtObjectBaseCmdletWithAccess<SymbolicLinkAccessRights>
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
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        return NtSymbolicLink.Open(obj_attributes, Access);
    }
}

