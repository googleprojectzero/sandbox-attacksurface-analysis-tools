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
    /// <para type="synopsis">Open a NT semaphore object by path.</para>
    /// <para type="description">This cmdlet opens an existing NT semaphore object (also known as a mutex). The absolute path to the object in the NT object manager name space must be specified. 
    /// It's also possible to create the object relative to an existing object by specified the -Root parameter.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = Get-NtSemaphore \BaseNamedObjects\ABC</code>
    ///   <para>Get a semaphore object with an absolute path.</para>
    /// </example>
    /// <example>
    ///   <code>$root = Get-NtDirectory \BaseNamedObjects&#x0A;$obj = Get-NtSemaphore ABC -Root $root</code>
    ///   <para>Get a semaphore object with a relative path.
    ///   </para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtSemaphore -Path \BaseNamedObjects\ABC&#x0A;$obj.Wait()&#x0A;# Do something in lock...&#x0A;$obj.Release()</code>
    ///   <para>Get a semaphore object, acquire the lock via Wait and Release it.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Get, "NtSemaphore")]
    [OutputType(typeof(NtSemaphore))]
    public sealed class GetNtSemaphoreCmdlet : NtObjectBaseCmdletWithAccess<SemaphoreAccessRights>
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
            return NtSemaphore.Open(obj_attributes, Access);
        }
    }

    /// <summary>
    /// <para type="synopsis">Create a new NT semaphore object.</para>
    /// <para type="description">This cmdlet creates a new NT semaphore object. The absolute path to the object in the NT object manager name space can be specified. 
    /// It's also possible to create the object relative to an existing object by specified the -Root parameter. If no path is specified than an unnamed object will be created which
    /// can only be duplicated by handle.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = New-NtSemaphore</code>
    ///   <para>Create a new anonymous semaphore object.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = New-NtSemaphore \BaseNamedObjects\ABC</code>
    ///   <para>Create a new semaphore object with an absolute path.</para>
    /// </example>
    /// <example>
    ///   <code>$root = Get-NtDirectory \BaseNamedObjects&#x0A;$obj = New-NtSemaphore ABC -Root $root</code>
    ///   <para>Create a new semaphore object with a relative path.
    ///   </para>
    /// </example>
    /// <example>
    ///   <code>$semaphore = New-NtSemaphore -MaximumCount 10</code>
    ///   <para>Create a new anonymous semaphore object a maximum count of 10.</para>
    /// </example>
    /// <example>
    ///   <code>$semaphore = New-NtSemaphore -InitialCount 1</code>
    ///   <para>Create a new anonymous semaphore object the initial count set to 1.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = New-NtSemaphore -InitialCount 1&#x0A;$semaphore.Wait(10)&#x0A;# Do something with the semaphore...&#x0A;$obj.Release(1)</code>
    ///   <para>Create a new anonymous semaphore object with an initial count of 1, decrement the semaphore via Wait with a 10 second wait and Release it.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.New, "NtSemaphore")]
    [OutputType(typeof(NtSemaphore))]
    public sealed class NewNtSemaphoreCmdlet : NtObjectBaseCmdletWithAccess<SemaphoreAccessRights>
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        public NewNtSemaphoreCmdlet()
        {
            MaximumCount = 1;
        }

        /// <summary>
        /// <para type="description">Specify the intial count of the semaphore.</para>
        /// </summary>
        [Parameter]
        public int InitialCount { get; set; }

        /// <summary>
        /// <para type="description">Specify the maximum count of the semaphore.</para>
        /// </summary>
        [Parameter]
        public int MaximumCount { get; set; }

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
            return NtSemaphore.Create(obj_attributes, Access, InitialCount, MaximumCount);
        }
    }
}
