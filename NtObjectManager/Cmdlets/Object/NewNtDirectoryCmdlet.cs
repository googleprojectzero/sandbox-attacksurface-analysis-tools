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
using NtCoreLib.Kernel.ObjectManager;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Create a new NT object directory by path.</para>
/// <para type="description">This cmdlet creates a new NT object directory. It's possible to create a directory by its NT path, such as \Some\Path
/// or it can also create a new private namespace which isn't represented by an accessible NT path but instead uses a boundary descriptor.</para>
/// </summary>
/// <example>
///   <code>$obj = New-NtDirectory</code>
///   <para>Create a new anonymous directory object.</para>
/// </example>
/// <example>
///   <code>$obj = New-NtDirectory \BaseNamedObjects\ABC</code>
///   <para>Create a new directory object with an absolute path.</para>
/// </example>
/// <example>
///   <code>$root = Get-NtDirectory \BaseNamedObjects&#x0A;$obj = New-NtDirectory ABC -Root $root</code>
///   <para>Create a new directory object with a relative path.
///   </para>
/// </example>
/// <example>
///   <code>cd NtObject:\BaseNamedObjects&#x0A;$obj = New-NtDirectory ABC</code>
///   <para>Create a new directory object with a relative path based on the current location.</para>
/// </example>
/// <example>
///   <code>$shadow = Get-NtDirectory \SomeDir&#x0A;$obj = New-NtDirectory \BaseNamedObjects\ABC -ShadowDirectory $shadow</code>
///   <para>Create a new directory object with a shadow directory.
///   </para>
/// </example>
/// <example>
///   <code>$obj = New-NtDirectory -PrivateNamespaceDescriptor WD:LW@ABC</code>
///   <para>Create a new private namespace directory object with Everyone and Low Mandatory Level SIDs and name ABC.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
/// <para type="link">https://msdn.microsoft.com/en-us/library/windows/desktop/ms682419%28v=vs.85%29.aspx</para>
/// <para type="link">https://msdn.microsoft.com/en-us/library/windows/desktop/ms682121(v=vs.85).aspx</para>
[Cmdlet(VerbsCommon.New, "NtDirectory")]
[OutputType(typeof(NtDirectory))]
public sealed class NewNtDirectoryCmdlet : GetNtDirectoryCmdlet
{
    /// <summary>
    /// <para type="description">Specifies another NT directory object to use as a shadown directory.
    /// This changes the lookup operation so that if an entry isn't in the created directory it will try
    /// and look it up in the shadown instead.
    /// </para>
    /// </summary>
    [Parameter]
    public NtDirectory ShadowDirectory { get; set; }

    /// <summary>
    /// <para type="description">Specifies flags to use when creating the directory object.
    /// </para>
    /// </summary>
    [Parameter]
    public DirectoryCreateFlags Flags { get; set; }

    /// <summary>
    /// Determine if the cmdlet can create objects.
    /// </summary>
    /// <returns>True if objects can be created.</returns>
    protected override bool CanCreateDirectories()
    {
        return PrivateNamespaceDescriptor == null;
    }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        if (PrivateNamespaceDescriptor != null)
        {
            using BoundaryDescriptor descriptor = BoundaryDescriptor.CreateFromString(PrivateNamespaceDescriptor);
            return NtDirectory.CreatePrivateNamespace(obj_attributes, descriptor, Access);
        }
        else
        {
            return NtDirectory.Create(obj_attributes, Access, ShadowDirectory, Flags);
        }
    }
}
