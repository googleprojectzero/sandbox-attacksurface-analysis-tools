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
    /// <para type="synopsis">Creates a new port section from a port.</para>
    /// <para type="description">This cmdlet creates a new port section with a specified size and flags for a port. You can then write to buffer and pass it as a view attribute.</para>
    /// </summary>
    /// <example>
    ///   <code>$s = New-NtAlpcPortSection -Size 10000</code>
    ///   <para>Create a new port section of size 10000.</para>
    /// </example>
    /// <example>
    ///   <code>$s = New-NtAlpcPortSection -Size 10000 -Secure</code>
    ///   <para>Create a new secure port section of size 10000.</para>
    /// </example>
    /// <example>
    ///   <code>$s = New-NtAlpcPortSection -Section $sect</code>
    ///   <para>>Create a new port section backed by an existing section.</para>
    /// </example>
    /// <example>
    ///   <code>$s = New-NtAlpcPortSection -Section $sect -Size 10000</code>
    ///   <para>>Create a new port section backed by an existing section with an explicit view size.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.New, "NtAlpcPortSection", DefaultParameterSetName = "FromSize")]
    [OutputType(typeof(AlpcPortSection))]
    public class NewNtAlpcPortSectionCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the port to create the port section from.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public NtAlpc Port { get; set; }

        /// <summary>
        /// <para type="description">Specify the size of the port section. This will be rounded up to the nearest allocation boundary.</para>
        /// </summary>
        [Parameter(Position = 1, Mandatory = true, ParameterSetName = "FromSize")]
        [Parameter(ParameterSetName = "FromSection")]
        public long Size { get; set; }

        /// <summary>
        /// <para type="description">Create a secure section.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromSize")]
        public SwitchParameter Secure { get; set; }

        /// <summary>
        /// <para type="description">Specify an existing section to back the port section.</para>
        /// </summary>
        [Parameter(Position = 1, Mandatory = true, ParameterSetName = "FromSection")]
        public NtSection Section { get; set; }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            switch (ParameterSetName)
            {
                case "FromSize":
                    WriteObject(Port.CreatePortSection(Secure ? AlpcCreatePortSectionFlags.Secure : 0, Size));
                    break;
                case "FromSection":
                    WriteObject(Port.CreatePortSection(AlpcCreatePortSectionFlags.None, Section, Size == 0 ? Section.Size : Size));
                    break;
            }
        }
    }
}
