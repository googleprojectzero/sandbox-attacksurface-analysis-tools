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

namespace NtObjectManager
{
    /// <summary>
    /// <para type="synopsis">Open a NT mutant object by path.</para>
    /// <para type="description">This cmdlet opens an existing NT mutant object (also known as a mutex). The absolute path to the object in the NT object manager name space must be specified. 
    /// It's also possible to create the object relative to an existing object by specified the -Root parameter.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = Get-NtMutant \BaseNamedObjects\ABC</code>
    ///   <para>Get a mutant object with an absolute path.</para>
    /// </example>
    /// <example>
    ///   <code>$root = Get-NtDirectory \BaseNamedObjects&#x0A;$obj = Get-NtMutant ABC -Root $root</code>
    ///   <para>Get a mutant object with a relative path.
    ///   </para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtMutant -Path \BaseNamedObjects\ABC&#x0A;$obj.Wait()&#x0A;# Do something in lock...&#x0A;$obj.Release()</code>
    ///   <para>Get a mutant object, acquire the lock via Wait and Release it.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Get, "NtMutant")]
    [OutputType(typeof(NtMutant))]
    public sealed class GetNtMutantCmdlet : NtObjectBaseCmdletWithAccess<MutantAccessRights>
    {
        /// <summary>
        /// <para type="description">The NT object manager path to the object to use.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        new public string Path { get; set; }

        /// <summary>
        /// Virtual method to return the value of the Path variable.
        /// </summary>
        /// <returns>The object path.</returns>
        protected override string GetPath()
        {
            return Path;
        }

        /// <summary>
        /// Determine if the cmdlet can create objects.
        /// </summary>
        /// <returns>True if objects can be created.</returns>
        protected override bool CanCreateDirectories()
        {
            return false;
        }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtMutant.Open(obj_attributes, Access);
        }
    }

    /// <summary>
    /// <para type="synopsis">Create a new NT mutant object.</para>
    /// <para type="description">This cmdlet creates a new NT mutant object (also known as a mutex). The absolute path to the object in the NT object manager name space can be specified. 
    /// It's also possible to create the object relative to an existing object by specified the -Root parameter. If no path is specified than an unnamed object will be created which
    /// can only be duplicated by handle.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = New-NtMutant</code>
    ///   <para>Create a new anonymous mutant object.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = New-NtMutant \BaseNamedObjects\ABC</code>
    ///   <para>Create a new mutant object with an absolute path.</para>
    /// </example>
    /// <example>
    ///   <code>$root = Get-NtDirectory \BaseNamedObjects&#x0A;$obj = New-NtMutant ABC -Root $root</code>
    ///   <para>Create a new mutant object with a relative path.
    ///   </para>
    /// </example>
    /// <example>
    ///   <code>$mutant = New-NtMutant -InitialOwner</code>
    ///   <para>Create a new anonymous mutant object with the caller as the initial owner.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = New-NtMutant&#x0A;$mutant.Wait()&#x0A;# Do something in lock...&#x0A;$obj.Release()</code>
    ///   <para>Create a new anonymous mutant object, acquire the lock via Wait and Release it.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.New, "NtMutant")]
    [OutputType(typeof(NtMutant))]
    public sealed class NewNtMutantCmdlet : NtObjectBaseCmdletWithAccess<MutantAccessRights>
    {
        /// <summary>
        /// <para type="description">Specify to indicate the caller is the initial owner of the mutant.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter InitialOwner { get; set; }


        /// <summary>
        /// Determine if the cmdlet can create objects.
        /// </summary>
        /// <returns>True if objects can be created.</returns>
        protected override bool CanCreateDirectories()
        {
            return true;
        }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtMutant.Create(obj_attributes, InitialOwner, Access);
        }
    }
}
