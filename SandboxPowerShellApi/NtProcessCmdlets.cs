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
    /// <para type="synopsis">Get NT processes.</para>
    /// <para type="description">This cmdlet gets all accessible processes on the system. You can specify a specific process by setting the -ProcessId parameter.</para>
    /// <para>Note that process objects need to be disposed of after use, therefore capture them in a Dispose List or manually Close them once used.</para>
    /// </summary>
    /// <example>
    ///   <code>$ps = Get-NtProcess | Push-NtDisposeList</code>
    ///   <para>Get all NT processes accessible by the current user and put then in a dispose list.</para>
    /// </example>
    /// <example>
    ///   <code>$ps = Get-NtProcess -Access DupHandle</code>
    ///   <para>Get all NT processes accessible by the current user for duplicate handle access.</para>
    /// </example>
    /// <example>
    ///   <code>$p = Get-NtProcess 1234</code>
    ///   <para>Get a specific process</para>
    /// </example>
    /// <example>
    ///   <code>$p = Get-NtProcess 1234 -Access QueryInformation&#x0A;$p.GetCommandLine()</code>
    ///   <para>Get a command line of a specific process.</para>
    /// </example>
    /// <example>
    ///   <code>$p = Get-NtProcess 1234 -Access QueryInformation&#x0A;$p.GetImageFileName($true)</code>
    ///   <para>Get a native image path of a specific process.</para>
    /// </example>
    /// <example>
    ///   <code>$p = Get-NtProcess $pid</code>
    ///   <para>Get the current process.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Get, "NtProcess")]
    [OutputType(typeof(NtProcess))]
    public class GetNtProcessCmdlet : Cmdlet
    {
        /// <summary>
        /// <para type="description">Specify a process ID to open.</para>
        /// </summary>
        [Parameter(Position = 0)]
        public int ProcessId { get; set; }

        /// <summary>
        /// <para type="description">Specify access rights for each process opened.</para>
        /// </summary>
        [Parameter]
        public ProcessAccessRights Access { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public GetNtProcessCmdlet()
        {
            Access = ProcessAccessRights.MaximumAllowed;
            ProcessId = -1;
        }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            if (ProcessId == -1)
            {
                WriteObject(NtProcess.GetProcesses(Access), true);
            }
            else
            {
                WriteObject(NtProcess.Open(ProcessId, Access));
            }
        }
    }
}
