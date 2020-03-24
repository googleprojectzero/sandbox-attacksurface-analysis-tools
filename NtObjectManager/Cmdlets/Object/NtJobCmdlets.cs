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
using System;
using System.Collections.Generic;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object
{
    /// <summary>
    /// <para type="synopsis">Open a NT job object by path.</para>
    /// <para type="description">This cmdlet opens an existing NT job object. The absolute path to the object in the NT object manager name space must be specified. 
    /// It's also possible to create the object relative to an existing object by specified the -Root parameter.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = Get-NtJob \BaseNamedObjects\ABC</code>
    ///   <para>Get an job object with an absolute path.</para>
    /// </example>
    /// <example>
    ///   <code>$root = Get-NtDirectory \BaseNamedObjects&#x0A;$obj = Get-NtJob ABC -Root $root</code>
    ///   <para>Get an job object with a relative path.</para>
    /// </example>
    /// <example>
    ///   <code>cd NtObject:\BaseNamedObjects&#x0A;$obj = Get-NtJob ABC</code>
    ///   <para>Get a job object with a relative path based on the current location.
    ///   </para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Get, "NtJob")]
    [OutputType(typeof(NtJob))]
    public sealed class GetNtJobCmdlet : NtObjectBaseCmdletWithAccess<JobAccessRights>
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
        public override string Path { get; set; }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtJob.Open(obj_attributes, Access);
        }
    }

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
                return job.Duplicate();
            }
        }
    }

    /// <summary>
    /// <para type="synopsis">Assign a process to a Job object.</para>
    /// <para type="description">This cmdlet assigns a process to a Job object.</para>
    /// </summary>
    /// <example>
    ///   <code>Set-NtProcessJob -Job $job -Process $process</code>
    ///   <para>Assigns the process to the job object.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Set, "NtProcessJob")]
    public sealed class SetNtProcessJobCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the job object.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0)]
        public NtJob Job { get; set; }

        /// <summary>
        /// <para type="description">Specify the list of processes to assign.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 1, ValueFromPipeline = true)]
        public NtProcess[] Process { get; set; }

        /// <summary>
        /// <para type="description">Specify to pass through the process objects.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter PassThru { get; set; }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            foreach (var proc in Process)
            {
                try
                {
                    Job.AssignProcess(proc);
                }
                catch (NtException ex)
                {
                    WriteError(new ErrorRecord(ex, "AssignJob", ErrorCategory.QuotaExceeded, proc));
                }

                if (PassThru)
                {
                    WriteObject(proc);
                }
            }
        }
    }

    /// <summary>
    /// <para type="synopsis">Gets the accessible Job objects assigned to a process.</para>
    /// <para type="description">This cmdlet gets the accessible Job objects for a process. This might not include all Jobs and might contain duplicates.</para>
    /// </summary>
    /// <example>
    ///   <code>Get-NtProcessJob -Process $process</code>
    ///   <para>Gets the Job objects assigned to the process.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Get, "NtProcessJob")]
    [OutputType(typeof(NtJob))]
    public sealed class GetNtProcessJobCmdlet : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the process to query.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0)]
        public NtProcess Process { get; set; }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            WriteObject(Process.GetAccessibleJobObjects(), true);
        }
    }

    /// <summary>
    /// <para type="description">Flags for formatting a job.</para>
    /// </summary>
    [Flags]
    public enum JobFormatFilter
    {
        /// <summary>
        /// Basic information.
        /// </summary>
        BasicInfo = 1,
        /// <summary>
        /// Basic limits.
        /// </summary>
        BasicLimits = 2,
        /// <summary>
        /// List of processes.
        /// </summary>
        ProcessList = 4,
        /// <summary>
        /// UI Limits.
        /// </summary>
        UILimits = 8,
        /// <summary>
        /// Display all formats.
        /// </summary>
        All = BasicLimits | ProcessList | BasicInfo | UILimits
    }

    /// <summary>
    /// <para type="synopsis">Formats Job information.</para>
    /// <para type="description">This cmdlet formats the Job information. Can either take a list of jobs or 
    /// a process.</para>
    /// </summary>
    /// <example>
    ///   <code>Format-NtJob -Job $job</code>
    ///   <para>Formats a job.</para>
    /// </example>
    /// <example>
    ///   <code>Format-NtJob -Process $process</code>
    ///   <para>Formats all accessible jobs for a process.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Format, "NtJob")]
    [OutputType(typeof(string))]
    public sealed class FormatNtJobCmdlet : PSCmdlet
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        public FormatNtJobCmdlet()
        {
            Filter = JobFormatFilter.All;
        }

        /// <summary>
        /// <para type="description">Specify the process to format job information.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromProcess")]
        public NtProcess Process { get; set; }

        /// <summary>
        /// <para type="description">Specify the process to format job information.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromJob")]
        public NtJob[] Job { get; set; }

        /// <summary>
        /// <para type="description">Specify what parts of the job to format.</para>
        /// </summary>
        [Parameter]
        public JobFormatFilter Filter { get; set; }

        private void FormatJobBasicLimits(NtJob job)
        {
            WriteObject("[Basic Limits]");
            WriteObject($"Limit Flags: {job.LimitFlags}");
            if (job.LimitFlags.HasFlag(JobObjectLimitFlags.ActiveProcess))
            {
                WriteObject($"Active Process Limit: {job.ActiveProcessLimit}");
            }
            if (job.LimitFlags.HasFlag(JobObjectLimitFlags.ProcessMemory))
            {
                WriteObject($"Process Memory Limit: {job.ProcessMemory}");
            }
            WriteObject(string.Empty);
        }

        private void FormatProcess(int pid)
        {
            using (var proc = NtProcess.Open(pid, ProcessAccessRights.QueryLimitedInformation, false))
            {
                if (!proc.IsSuccess)
                {
                    WriteObject($"{pid}: UNKNOWN");
                }
                else
                {
                    WriteObject($"{pid}: {proc.Result.Name}");
                }
            }
        }

        private void FormatProcessList(NtJob job)
        {
            var pids = job.GetProcessIdList(false);
            if (pids.IsSuccess)
            {
                WriteObject("[Process List]");
                foreach (var pid in pids.Result)
                {
                    FormatProcess(pid);
                }
                WriteObject(string.Empty);
            }
        }

        private void FormatBasicInfo(NtJob job)
        {
            WriteObject("[Basic Information]");
            WriteObject($"Handle: {job.Handle}");
            if (job.FullPath.Length > 0)
            {
                WriteObject($"Path: {job.FullPath}");
            }
            WriteObject(string.Empty);
        }

        private void FormatUILimits(NtJob job)
        {
            WriteObject("[UI Limits]");
            WriteObject($"Limit Flags: {job.UiRestrictionFlags}");
            WriteObject(string.Empty);
        }

        private void FormatJob(NtJob job)
        {
            if (Filter.HasFlag(JobFormatFilter.BasicInfo))
            {
                FormatBasicInfo(job);
            }
            if (Filter.HasFlag(JobFormatFilter.BasicLimits))
            {
                FormatJobBasicLimits(job);
            }
            if (Filter.HasFlag(JobFormatFilter.ProcessList))
            {
                FormatProcessList(job);
            }
            if (Filter.HasFlag(JobFormatFilter.UILimits))
            {
                FormatUILimits(job);
            }
        }

        private void FormatJobs(IEnumerable<NtJob> jobs)
        {
            foreach (var job in jobs)
            {
                FormatJob(job);
            }
        }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            if (ParameterSetName == "FromProcess")
            {
                using (var jobs = Process.GetAccessibleJobObjects().ToDisposableList())
                {
                    FormatJobs(jobs);
                }
            }
            else
            {
                FormatJobs(Job);
            }
        }
    }
}