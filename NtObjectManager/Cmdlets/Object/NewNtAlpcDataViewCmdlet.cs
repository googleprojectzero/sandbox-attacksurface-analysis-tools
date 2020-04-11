//  Copyright 2019 Google Inc. All Rights Reserved.
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
    /// <para type="synopsis">Creates a new data view from a port section.</para>
    /// <para type="description">This cmdlet creates a new data view from a port section specified size and flags.</para>
    /// </summary>
    /// <example>
    ///   <code>$s = New-NtAlpcDataView -Section $section -Size 10000</code>
    ///   <para>Create a new data view with size 10000.</para>
    /// </example>
    /// <example>
    ///   <code>$s = New-NtAlpcDataView -Size 10000 -Flags Secure</code>
    ///   <para>Create a new secure data view section of size 10000.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.New, "NtAlpcDataView")]
    [OutputType(typeof(SafeAlpcDataViewBuffer))]
    public class NewNtAlpcDataViewCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the port to create the port section from.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public AlpcPortSection Section { get; set; }

        /// <summary>
        /// <para type="description">Specify the size of the data view. This will be rounded up to the nearest allocation boundary.</para>
        /// </summary>
        [Parameter(Position = 1)]
        public long Size { get; set; }

        /// <summary>
        /// <para type="description">Specify data view attribute flags.</para>
        /// </summary>
        [Parameter]
        public AlpcDataViewAttrFlags Flags { get; set; }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            WriteObject(Section.CreateSectionView(Flags, Size == 0 ? Section.Size : Size));
        }
    }
}
