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
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="synopsis">Get NT handle information.</para>
    /// <para type="description">This cmdlet gets handle information for all process on the system. You can specify a specific process by setting the -ProcessId parameter.</para>
    /// <para>By default extra information about the handle will be queried. This comes at a cost and could cause the process to hang, therefore if you don't want to query
    /// pass the -NoQuery parameter.</para>
    /// </summary>
    /// <example>
    ///   <code>Get-NtHandle</code>
    ///   <para>Get all NT handles.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtHandle 1234</code>
    ///   <para>Get all NT handles filtered to a specific Process ID</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtHandle $pid</code>
    ///   <para>Get all NT handles for the current process.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtHandle 1234 -NoQuery</code>
    ///   <para>Get all NT handles filtered to a specific Process ID but don't try and query information about the handle such as name.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "NtHandle")]
    [OutputType(typeof(NtHandle))]
    public class GetNtHandleCmdlet : Cmdlet
    {
        /// <summary>
        /// <para type="description">Specify a process ID to filter handles on.</para>
        /// </summary>
        [Parameter(Position = 0)]
        [Alias(new string[] { "pid" })]
        public int ProcessId { get; set; }

        /// <summary>
        /// <para type="description">Specify that the returned handle entries should not be queried for additional information.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter NoQuery { get; set; }

        /// <summary>
        /// <para type="description">Specify list of object types to filter handles.</para>
        /// </summary>
        [Parameter]
        public string[] ObjectTypes { get; set; }
        
        /// <summary>
        /// Constructor.
        /// </summary>
        public GetNtHandleCmdlet()
        {
            ProcessId = -1;
        }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            IEnumerable<NtHandle> handles = NtSystemInfo.GetHandles(ProcessId, !NoQuery);
            if (ObjectTypes != null && ObjectTypes.Length > 0)
            {
                HashSet<string> object_types = new HashSet<string>(ObjectTypes, StringComparer.OrdinalIgnoreCase);
                handles = handles.Where(h => object_types.Contains(h.ObjectType));
            }
            WriteObject(handles, true);
        }
    }
}
