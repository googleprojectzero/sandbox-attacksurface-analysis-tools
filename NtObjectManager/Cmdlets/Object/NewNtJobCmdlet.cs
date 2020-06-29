//  Copyright 2016, 2017 Google Inc. All Rights Reserved.
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

namespace NtObjectManager.Cmdlets.Object
{
    /// <summary>
    /// <para type="synopsis">Create a new NT job object.</para>
    /// <para type="description">This cmdlet creates a new NT job object. The absolute path to the object in the NT object manager name space can be specified. 
    /// It's also possible to create the object relative to an existing object by specified the -Root parameter. If no path is specified than an unnamed object will be created which
    /// can only be duplicated by handle.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = New-NtJob</code>
    ///   <para>Create a new anonymous job object.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = New-NtJob \BaseNamedObjects\ABC</code>
    ///   <para>Create a new job object with an absolute path.</para>
    /// </example>
    /// <example>
    ///   <code>$root = Get-NtDirectory \BaseNamedObjects&#x0A;$obj = New-NtJob ABC -Root $root</code>
    ///   <para>Create a new job object with a relative path.
    ///   </para>
    /// </example>
    /// <example>
    ///   <code>cd NtObject:\BaseNamedObjects&#x0A;$obj = New-NtJob ABC</code>
    ///   <para>Create a new job object with a relative path based on the current location.
    ///   </para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.New, "NtJob")]
    [OutputType(typeof(NtJob))]
    public sealed class NewNtJobCmdlet : NtObjectBaseCmdletWithAccess<JobAccessRights>
    {
        /// <summary>
        /// <para type="description">Specify a process limit for the job.</para>
        /// </summary>
        [Parameter]
        public int ActiveProcessLimit { get; set; }

        /// <summary>
        /// <para type="description">Specify limit flags for the job.</para>
        /// </summary>
        [Parameter]
        public JobObjectLimitFlags LimitFlags { get; set; }

        /// <summary>
        /// <para type="description">Specify UI Restriction flags for the job.</para>
        /// </summary>
        [Parameter]
        public JobObjectUiLimitFlags UiRestrictionFlags { get; set; }

        /// <summary>
        /// <para type="description">Specify to create Job as a Silo.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter CreateSilo { get; set; }

        /// <summary>
        /// <para type="description">Specify to flags when creating the Silo's root directory. Must be used with -Silo.</para>
        /// </summary>
        [Parameter]
        public SiloObjectRootDirectoryControlFlags SiloRootDirectoryFlags { get; set; }

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
            using (var job = NtJob.Create(obj_attributes, Access))
            {
                if (LimitFlags != 0)
                {
                    job.LimitFlags = LimitFlags;
                }
                if (ActiveProcessLimit > 0)
                {
                    job.ActiveProcessLimit = ActiveProcessLimit;
                }
                if (UiRestrictionFlags != 0)
                {
                    job.UiRestrictionFlags = UiRestrictionFlags;
                }
                if (CreateSilo)
                {
                    job.InitializeSilo(SiloRootDirectoryFlags);
                }

                return job.Duplicate();
            }
        }
    }
}