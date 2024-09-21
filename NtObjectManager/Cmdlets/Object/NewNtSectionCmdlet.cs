//  Copyright 2017 Google Inc. All Rights Reserved.
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
/// <para type="synopsis">Create a new NT section object.</para>
/// <para type="description">This cmdlet creates a new NT section object. The absolute path to the object in the NT object manager name space can be specified. 
/// It's also possible to create the object relative to an existing object by specified the -Root parameter. If no path is specified than an unnamed object will be created which
/// can only be duplicated by handle.</para>
/// </summary>
/// <example>
///   <code>$obj = New-NtSection -Size 4096</code>
///   <para>Create a new anonymous section object of size 4096 bytes.</para>
/// </example>
/// <example>
///   <code>$obj = New-NtSection \BaseNamedObjects\ABC -Size 4096</code>
///   <para>Create a new section object with an absolute path.</para>
/// </example>
/// <example>
///   <code>$file = Get-NtFile \??\C:\SomeFile&#x0A;$obj = New-NtSection -File $file -Protection ReadOnly</code>
///   <para>Create a new section object backed by a file with read only protection.
///   </para>
/// </example>
/// <example>
///   <code>$file = Get-NtFile \??\C:\Windows\notepad.exe&#x0A;$obj = New-NtSection -File $file -SectionAttributes Image -Protection ReadOnly</code>
///   <para>Create a new image section object backed by an executable file.
///   </para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.New, "NtSection")]
[OutputType(typeof(NtSection))]
public sealed class NewNtSectionCmdlet : NtObjectBaseCmdletWithAccess<SectionAccessRights>
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
    /// <para type="description">An existing file to use as backing for the section.</para>
    /// </summary>
    [Parameter]
    public NtFile File { get; set; }

    /// <summary>
    /// <para type="description">An optional size for the section.</para>
    /// </summary>
    [Parameter]
    public LargeInteger Size { get; set; }

    /// <summary>
    /// <para type="description">Memory allocation protection flags.</para>
    /// </summary>
    [Parameter]
    public MemoryAllocationProtect Protection { get; set; }

    /// <summary>
    /// <para type="description">Section attribute flags.</para>
    /// </summary>
    [Parameter]
    public SectionAttributes SectionAttributes { get; set; }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        return NtSection.Create(obj_attributes, Access, Size, Protection, SectionAttributes, File);
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    public NewNtSectionCmdlet()
    {
        Protection = MemoryAllocationProtect.ReadWrite;
        SectionAttributes = SectionAttributes.Commit;
    }
}
