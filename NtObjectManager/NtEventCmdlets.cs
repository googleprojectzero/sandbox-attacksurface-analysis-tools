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
    /// <para type="synopsis">Open a NT event object by path.</para>
    /// <para type="description">This cmdlet opens an existing NT event object. The absolute path to the object in the NT object manager name space must be specified. 
    /// It's also possible to create the object relative to an existing object by specified the -Root parameter.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = Get-NtEvent \BaseNamedObjects\ABC</code>
    ///   <para>Get an event object with an absolute path.</para>
    /// </example>
    /// <example>
    ///   <code>$root = Get-NtDirectory \BaseNamedObjects&#x0A;$obj = Get-NtEvent ABC -Root $root</code>
    ///   <para>Get an event object with a relative path.
    ///   </para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtEvent -Path \BaseNamedObjects\ABC&#x0A;$obj.Wait()</code>
    ///   <para>Get an event object, wait for it to be set.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtEvent -Path \BaseNamedObjects\ABC&#x0A;$obj.Set()</code>
    ///   <para>Get an event object, and set it.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Get, "NtEvent")]
    [OutputType(typeof(NtEvent))]
    public sealed class GetNtEventCmdlet : NtObjectBaseCmdletWithAccess<EventAccessRights>
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
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtEvent.Open(obj_attributes, Access);
        }
    }

    /// <summary>
    /// <para type="synopsis">Create a new NT event object.</para>
    /// <para type="description">This cmdlet creates a new NT event object. The absolute path to the object in the NT object manager name space can be specified. 
    /// It's also possible to create the object relative to an existing object by specified the -Root parameter. If no path is specified than an unnamed object will be created which
    /// can only be duplicated by handle.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = New-NtEvent</code>
    ///   <para>Create a new anonymous event object.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = New-NtEvent \BaseNamedObjects\ABC</code>
    ///   <para>Create a new event object with an absolute path.</para>
    /// </example>
    /// <example>
    ///   <code>$root = Get-NtDirectory \BaseNamedObjects&#x0A;$obj = New-NtEvent ABC -Root $root</code>
    ///   <para>Create a new event object with a relative path.
    ///   </para>
    /// </example>
    /// <example>
    ///   <code>$mutant = New-NtEvent -InitialState $true</code>
    ///   <para>Create a new anonymous event object with it initially set.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = New-NtEvent -Path \BaseNamedObjects\ABC&#x0A;$obj.Wait()</code>
    ///   <para>Create a new event object, wait for it to be set.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = New-NtEvent -Path \BaseNamedObjects\ABC&#x0A;$obj.Set()</code>
    ///   <para>Create a new event object, and set it.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.New, "NtEvent")]
    [OutputType(typeof(NtEvent))]
    public sealed class NewNtEventCmdlet : NtObjectBaseCmdletWithAccess<EventAccessRights>
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
        /// <para type="description">The initial state of the event object.</para>
        /// </summary>
        [Parameter]
        public bool InitialState { get; set; }

        /// <summary>
        /// <para type="description">The type of event to create.</para>
        /// </summary>
        [Parameter]
        public EventType EventType { get; set; }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtEvent.Create(obj_attributes, EventType, InitialState, Access);
        }
    }
}
