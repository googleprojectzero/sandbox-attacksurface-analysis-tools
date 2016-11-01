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

using NtApiDotNet;
using System.Management.Automation;
using System;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="synopsis">Open a NT object directory.</para>
    /// <para type="description">This cmdlet opens an existing NT object directory. It's possible to open a directory by its NT path, such as \Some\Path
    /// or it can also open a private namespace which isn't represented by an accessible NT path but instead uses a boundary descriptor.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = Get-NtDirectory \BaseNamedObjects</code>
    ///   <para>Get a directory object with an absolute path.</para>
    /// </example>
    /// <example>
    ///   <code>$root = Get-NtDirectory \BaseNamedObjects&#x0A;$obj = Get-NtDirectory ABC -Root $root</code>
    ///   <para>Get a mutant object with a relative path.
    ///   </para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtDirectory -Path \BaseNamedObjects&#x0A;$obj.Query()</code>
    ///   <para>Get a directory object and query its list of entries.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtDirectory -PrivateNamespaceDescriptor WD:LW@ABC</code>
    ///   <para>Get a private namespace directory object with Everyone and Low Mandatory Level SIDs and name ABC.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    /// <para type="link">https://msdn.microsoft.com/en-us/library/windows/desktop/ms684318(v=vs.85).aspx</para>
    /// <para type="link">https://msdn.microsoft.com/en-us/library/windows/desktop/ms682121(v=vs.85).aspx</para>
    [Cmdlet(VerbsCommon.Get, "NtDirectory")]
    [OutputType(typeof(NtDirectory))]
    public class GetNtDirectoryCmdlet : NtObjectBaseCmdletWithAccess<DirectoryAccessRights>
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
        /// <para type="description">A string format of a private namespace boundary descriptor.
        /// Uses the form [SID[:SID...]@]NAME where SID is an SDDL version of a SID to add to the
        /// boundary (such as S-X-X-X or WD) and NAME is the arbitrary name.
        /// </para>
        /// </summary>
        [Parameter]
        public string PrivateNamespaceDescriptor { get; set; }

        /// <summary>
        /// Virtual method to return the value of the Path variable.
        /// </summary>
        /// <returns>The object path.</returns>
        protected override string GetPath()
        {
            if (PrivateNamespaceDescriptor != null)
            {
                return null;
            }
            else
            {
                return base.GetPath();
            }
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
                using (BoundaryDescriptor descriptor = BoundaryDescriptor.CreateFromString(PrivateNamespaceDescriptor))
                {
                    return NtDirectory.OpenPrivateNamespace(obj_attributes, descriptor, Access);
                }
            }
            else
            {
                return NtDirectory.Open(obj_attributes, Access);
            }
        }
    }

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
                using (BoundaryDescriptor descriptor = BoundaryDescriptor.CreateFromString(PrivateNamespaceDescriptor))
                {
                    return NtDirectory.CreatePrivateNamespace(obj_attributes, descriptor, Access);
                }
            }
            else
            {
                return NtDirectory.Create(obj_attributes, Access, ShadowDirectory);
            }
        }
    }
}
