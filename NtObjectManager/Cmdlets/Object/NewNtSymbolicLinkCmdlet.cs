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
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;


/// <summary>
/// <para type="synopsis">Create a new NT symbolic link object.</para>
/// <para type="description">This cmdlet creates a new NT symbolic link object. The absolute path to the object in the NT object manager name space can be specified. 
/// It's also possible to create the object relative to an existing object by specified the -Root parameter. If no path is specified than an unnamed object will be created which
/// can only be duplicated by handle.</para>
/// </summary>
/// <example>
///   <code>$obj = New-NtSymbolicLink -TargetPath \Symlink\Target</code>
///   <para>Create a new anonymous symbolic link object.</para>
/// </example>
/// <example>
///   <code>$obj =  New-NtSymbolicLink \DosDevices\ABC \Symlink\Target</code>
///   <para>Create a new symbolic link object with an absolute path.</para>
/// </example>
/// <example>
///   <code>$root = Get-NtDirectory \DosDevices&#x0A;$obj = New-NtSymbolicLink ABC \Symlink\Target -Root $root</code>
///   <para>Create a new symbolic link object with a relative path.
///   </para>
/// </example>
/// <example>
///   <code>cd NtObject:\BaseNamedObjects&#x0A;$obj = New-NtSymbolicLink ABC \Symlink\Target</code>
///   <para>Create a new symbolic link object with a relative path based on the current location.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.New, "NtSymbolicLink")]
public class NewNtSymbolicLinkCmdlet : NtObjectBaseCmdletWithAccess<SymbolicLinkAccessRights>
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
    /// <para type="description">Specify the target NT object manager path to follow if processing this symbolic link.</para>
    /// </summary>
    [Parameter(Position = 1, Mandatory = true), AllowEmptyString()]
    public string TargetPath { get; set; }

    /// <summary>
    /// <para type="description">Specify to create a global symbolic link. You need SeTcbPrivilege for this call to succeed.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter Global { get; set; }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        if (TargetPath == null)
        {
            throw new ArgumentNullException("TargetPath");
        }

        if (Global)
        {
            using var link = NtSymbolicLink.Create(obj_attributes, Access | SymbolicLinkAccessRights.Set, TargetPath);
            link.SetGlobalLink();
            return link.Duplicate();
        }

        return NtSymbolicLink.Create(obj_attributes, Access, TargetPath);
    }
}

