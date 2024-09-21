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

using NtCoreLib;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

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
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "FromJob", ValueFromPipeline = true)]
    public NtJob[] Job { get; set; }

    /// <summary>
    /// <para type="description">Specify what parts of the job to format.</para>
    /// </summary>
    [Parameter]
    public JobFormatFilter Filter { get; set; }

    private void FormatJobBasicLimits(NtJob job)
    {
        WriteObject("[Basic Limits]");
        WriteObject($"Limit Flags         : {job.LimitFlags}");
        if (job.LimitFlags.HasFlag(JobObjectLimitFlags.ActiveProcess))
        {
            WriteObject($"Active Process Limit: {job.ActiveProcess}");
        }
        if (job.LimitFlags.HasFlag(JobObjectLimitFlags.ProcessMemory))
        {
            WriteObject($"Process Memory Limit: {job.ProcessMemory}");
        }
        if (job.LimitFlags.HasFlag(JobObjectLimitFlags.ProcessTime))
        {
            WriteObject($"Process Time Limit  : {FormatTime(job.ProcessTime)}");
        }
        if (job.LimitFlags.HasFlag(JobObjectLimitFlags.JobMemory))
        {
            WriteObject($"Job Memory Limit    : {job.JobMemory}");
        }
        if (job.LimitFlags.HasFlag(JobObjectLimitFlags.JobTime))
        {
            WriteObject($"Job Time Limit      : {FormatTime(job.JobTime)}");
        }
        WriteObject(string.Empty);
    }

    private static string FormatTime(long time)
    {
        double time_curr_ms = Math.Abs(time) / 10000.0;
        return $"{time_curr_ms / 1000}s";
    }

    private void FormatProcess(int pid)
    {
        using var proc = NtProcess.Open(pid, ProcessAccessRights.QueryLimitedInformation, false);
        if (!proc.IsSuccess)
        {
            WriteObject($"{pid}: UNKNOWN");
        }
        else
        {
            WriteObject($"{pid}: {proc.Result.Name}");
        }
    }

    private void FormatProcessList(NtJob job)
    {
        var pids = job.GetProcessIdList(false);
        if (pids.IsSuccess && pids.Result.Any())
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

    private void FormatSilo(NtJob job)
    {
        var basic_info = job.QuerySiloBasicInformation(false);
        if (!basic_info.IsSuccess)
            return;
        WriteObject("[Silo]");
        WriteObject($"Silo ID       : {basic_info.Result.SiloId}");
        WriteObject($"Silo Parent ID: {basic_info.Result.SiloParentId}");
        WriteObject($"Process Count : {basic_info.Result.NumberOfProcesses}");
        string root_dir = job.QuerySiloRootDirectory(false).GetResultOrDefault(string.Empty);
        if (root_dir.Length > 0)
        {
            WriteObject($"Root Directory: {root_dir}");
        }
        WriteObject($"Container ID  : {job.ContainerId}");
        if (job.ContainerTelemetryId != Guid.Empty)
        {
            WriteObject($"Telemetry ID  : {job.ContainerTelemetryId}");
        }
        WriteObject($"Impersonation : {(job.ThreadImpersonation ? "Enabled" : "Disabled")}");
        WriteObject(string.Empty);
        if (!basic_info.Result.IsInServerSilo)
            return;
        var server_info = job.QueryServerSiloBasicInformation(false);
        if (!server_info.IsSuccess)
            return;
        WriteObject("[Server Silo]");
        WriteObject($"Session ID    : {server_info.Result.ServiceSessionId}");
        WriteObject($"Exit Status   : {server_info.Result.ExitStatus}");
        WriteObject($"State         : {server_info.Result.State}");
        WriteObject($"Downlevel     : {server_info.Result.IsDownlevelContainer}");
        WriteObject(string.Empty);
        var user_data = job.QuerySiloUserSharedData(false);
        if (!user_data.IsSuccess)
            return;
        WriteObject("[Silo Shared User Data]");
        WriteObject($"Console ID    : {user_data.Result.ActiveConsoleId}");
        WriteObject($"Foreground PID: {user_data.Result.ConsoleSessionForegroundProcessId}");
        WriteObject($"Service SID   : {user_data.Result.ServiceSessionId}");
        WriteObject($"User SID      : {user_data.Result.SharedUserSessionId}");
        WriteObject($"System Root   : {user_data.Result.NtSystemRoot}");
        WriteObject($"NT Product    : {user_data.Result.NtProductType}");
        WriteObject($"Multisession  : {user_data.Result.IsMultiSessionSku}");
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
        if (Filter.HasFlag(JobFormatFilter.Silo))
        {
            FormatSilo(job);
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
            using var jobs = Process.GetAccessibleJobObjects().ToDisposableList();
            FormatJobs(jobs);
        }
        else
        {
            FormatJobs(Job);
        }
    }
}