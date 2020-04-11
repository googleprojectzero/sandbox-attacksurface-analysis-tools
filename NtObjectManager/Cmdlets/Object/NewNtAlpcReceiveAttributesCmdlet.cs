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
    /// <para type="synopsis">Creates a new receive attributes buffer.</para>
    /// <para type="description">This cmdlet creates a new receive attributes buffer for the specified set of attributes. This defaults to all known attributes.</para>
    /// </summary>
    /// <example>
    ///   <code>$attrs = New-NtAlpcReceiveAttributes</code>
    ///   <para>Create a new receive attributes buffer with space for all known attributes.</para>
    /// </example>
    /// <example>
    ///   <code>$attrs = New-NtAlpcReceiveAttributes -Attributes View, Context</code>
    ///   <para>Create a new receive attributes buffer with space for only View and Context attributes.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.New, "NtAlpcReceiveAttributes")]
    [OutputType(typeof(AlpcReceiveMessageAttributes))]
    public class NewNtAlpcReceiveAttributesCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the list of attributes for the receive buffer.</para>
        /// </summary>
        [Parameter(Position = 0)]
        public AlpcMessageAttributeFlags Attributes { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public NewNtAlpcReceiveAttributesCmdlet()
        {
            Attributes = AlpcMessageAttributeFlags.AllAttributes;
        }

        /// <summary>
        /// Process record.
        /// </summary>
        protected override void ProcessRecord()
        {
            WriteObject(new AlpcReceiveMessageAttributes(Attributes));
        }
    }
}
