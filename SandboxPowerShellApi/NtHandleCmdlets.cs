//  Copyright 2016 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
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
    /// <para type="synopsis">Get NT handle information.</para>
    /// <para type="description">This cmdlet gets handle information for all process on the system. You can specify a specific process by setting the -ProcessId parameter.</para>
    /// <para>By default
    /// outside of what's provided by the system the handle entries will not query for information such as handle names. If you want to do this then set the -Query parameter. Querying
    /// comes at a cost, it might cause the process to hang. Also it's requires that the caller has access to the target process to do the query. Finally querying will increase the time
    /// it takes to list the handles.</para>
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
    ///   <code>Get-NtHandle 1234 -Query</code>
    ///   <para>Get all NT handles filtered to a specific Process ID and try and query information about the handle such as name.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "NtHandle")]
    [OutputType(typeof(NtHandle))]
    public class GetNtHandleCmdlet : Cmdlet
    {
        /// <summary>
        /// <para type="description">Specify a process ID to filter handles on.</para>
        /// </summary>
        [Parameter(Position = 0)]
        public int ProcessId { get; set; }

        /// <summary>
        /// <para type="description">Specify that the returned handle entries can be queried for additional information.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter Query { get; set; }
        
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
            WriteObject(NtSystemInfo.GetHandles(ProcessId, Query), true);
        }
    }
}
