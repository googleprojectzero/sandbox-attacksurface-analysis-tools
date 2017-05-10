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
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="synopsis">Get NT processes.</para>
    /// <para type="description">This cmdlet gets all accessible processes on the system. You can specify a specific process by setting the -ProcessId parameter.</para>
    /// <para>Note that process objects need to be disposed of after use, therefore capture them in a Dispose List or manually Close them once used. You can specify
    /// some specific filters for the list of processes returned. The advantage of filtering here is the created NtProcess objects will be automatically disposed of
    /// when not needed.</para>
    /// </summary>
    /// <example>
    ///   <code>$ps = Get-NtProcess</code>
    ///   <para>Get all NT processes accessible by the current user.</para>
    /// </example>
    /// <example>
    ///   <code>$p = Get-NtProcess -Current</code>
    ///   <para>Get reference to current process.</para>
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
    ///   <code>$p = Get-NtProcess 1234 -Access QueryInformation&#x0A;$p.CommandLine</code>
    ///   <para>Get a command line of a specific process.</para>
    /// </example>
    /// <example>
    ///   <code>$p = Get-NtProcess 1234 -Access QueryInformation&#x0A;$p.FullPath</code>
    ///   <para>Get a native image path of a specific process.</para>
    /// </example>
    /// <example>
    ///   <code>$p = Get-NtProcess $pid</code>
    ///   <para>Get the current process.</para>
    /// </example>
    /// <example>
    ///   <code>$ps = Get-NtProcess -Name notepad.exe</code>
    ///   <para>Get all processes with the name notepad.exe.</para>
    /// </example>
    /// <example>
    ///   <code>$ps = Get-NtProcess -CommandLine hello</code>
    ///   <para>Get all processes with where the command line contains the string "hello".</para>
    /// </example>
    /// <example>
    ///   <code>$ps = Get-NtProcess -Name notepad.exe -CommandLine hello</code>
    ///   <para>Get all processes with the name notepad.exe where the command line contains the string "hello".</para>
    /// </example>
    /// <example>
    ///   <code>$ps = Get-NtProcess -FilterScript { param($p); p.SessionId -eq 1 }</code>
    ///   <para>Get all processes in session 1.</para>
    /// </example>
    /// <example>
    ///   <code>$ps = Get-NtProcess -FilterScript { param($p); $p.Mitigations.DisallowWin32kSystemCalls -eq $true }</code>
    ///   <para>Get all processes with the Disallow Win32k System Calls mitigation policy.</para>
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
        [Alias(new string[] { "pid" })]
        public int ProcessId { get; set; }

        /// <summary>
        /// <para type="description">Specify a executable name to filter the list on.</para>
        /// </summary>
        [Parameter]
        public string Name { get; set; }

        /// <summary>
        /// <para type="description">Specify sub-string in the command line to filter the list on. If Name is also specified this will just select processes with that name with this sub-string.</para>
        /// </summary>
        [Parameter]
        public string CommandLine { get; set; }

        /// <summary>
        /// <para type="description">Specify an arbitrary filter script.</para>
        /// </summary>
        [Parameter]
        public ScriptBlock FilterScript { get; set; }

        /// <summary>
        /// <para type="description">Specify access rights for each process opened.</para>
        /// </summary>
        [Parameter]
        public ProcessAccessRights Access { get; set; }

        /// <summary>
        /// <para type="description">Open current process.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter Current { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public GetNtProcessCmdlet()
        {
            Access = ProcessAccessRights.MaximumAllowed;
            ProcessId = -1;
        }

        private static bool FilterName(NtProcess proc, string name)
        {
            try
            {
                return proc.Name.Equals(name, System.StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
            }

            return false;
        }

        private static bool FilterCommandLine(NtProcess proc, string cmdline)
        {
            try
            {
                return proc.CommandLine.ToLower().Contains(cmdline);
            }
            catch
            {
            }

            return false;
        }

        private static bool ArbitraryFilter(NtProcess proc, ScriptBlock filter)
        {
            try
            {
                ICollection<PSObject> os = filter.Invoke(proc);
                if (os.Count == 1)
                {
                    return (bool)os.First().BaseObject;
                }
            }
            catch
            {
            }

            return false;
        }

        private IEnumerable<NtObject> GetProcesses()
        {
            if (string.IsNullOrWhiteSpace(Name) && string.IsNullOrWhiteSpace(CommandLine) && FilterScript == null)
            {
                return NtProcess.GetProcesses(Access);
            }

            using (DisposableList<NtProcess> procs = new DisposableList<NtProcess>(NtProcess.GetProcesses(Access)))
            {
                IEnumerable<NtProcess> filtered_procs = procs;
                if (!string.IsNullOrWhiteSpace(Name))
                {
                    filtered_procs = filtered_procs.Where(p => FilterName(p, Name));
                }
                if (!string.IsNullOrWhiteSpace(CommandLine))
                {
                    filtered_procs = filtered_procs.Where(p => FilterCommandLine(p, CommandLine));
                }
                if (FilterScript != null)
                {
                    filtered_procs = filtered_procs.Where(p => ArbitraryFilter(p, FilterScript));
                }
                return filtered_procs.Select(p => p.Duplicate()).ToArray();
            }
        }

        private static NtProcess GetCurrentProcess(ProcessAccessRights access)
        {
            if ((access & ProcessAccessRights.MaximumAllowed) == ProcessAccessRights.MaximumAllowed)
            {
                return NtProcess.Current;
            }
            else
            {
                return NtProcess.Current.Duplicate(access);
            }
        }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            if (ProcessId == -1 && !Current)
            {
                WriteObject(GetProcesses(), true);
            }
            else
            {
                WriteObject(Current ? GetCurrentProcess(Access) : NtProcess.Open(ProcessId, Access));
            }
        }
    }
}
