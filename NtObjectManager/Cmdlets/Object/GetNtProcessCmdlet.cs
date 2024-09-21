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

using NtCoreLib;
using NtCoreLib.Utilities.Collections;
using NtCoreLib.Win32.Service;
using NtObjectManager.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Get NT processes.</para>
/// <para type="description">This cmdlet gets all accessible processes on the system. You can specify a specific process by setting the -ProcessId or -Current parameters.</para>
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
///   <para>Get the current process by process ID.</para>
/// </example>
/// <example>
///   <code>$p = Get-NtProcess 1234 -OpenParent</code>
///   <para>Get the parent of a specific process.</para>
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
///   <code>$ps = Get-NtProcess -FilterScript { $_.SessionId -eq 1 }</code>
///   <para>Get all processes in session 1.</para>
/// </example>
/// <example>
///   <code>$ps = Get-NtProcess -FilterScript { $_.Mitigations.DisallowWin32kSystemCalls -eq $true }</code>
///   <para>Get all processes with the Disallow Win32k System Calls mitigation policy.</para>
/// </example>
/// <example>
///   <code>$p = Get-NtProcess -ServiceName WebClient</code>
///   <para>Open the process which hosts the WebClient service, if it's running.</para>
/// </example>
/// <example>
///   <code>Get-NtProcess -InfoOnly</code>
///   <para>Get all process information, don't open the process objects.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.Get, "NtProcess", DefaultParameterSetName = "all")]
[OutputType(typeof(NtProcess), typeof(NtProcessInformation))]
public class GetNtProcessCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify a process ID to open.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "pid"), 
        Parameter(Mandatory = true, ParameterSetName = "pidinfo")]
    [Alias(new string[] { "pid" })]
    public int ProcessId { get; set; }

    /// <summary>
    /// <para type="description">When opening a specific process choose whether to open its parent instead.</para>
    /// </summary>
    [Parameter(ParameterSetName = "pid"), Parameter(ParameterSetName = "current")]
    public SwitchParameter OpenParent { get; set; }

    /// <summary>
    /// <para type="description">When opening a specific process choose whether to open its 
    /// owner process (which is typically a console host) instead.</para>
    /// </summary>
    [Parameter(ParameterSetName = "pid"), Parameter(ParameterSetName = "current")]
    public SwitchParameter OpenOwner { get; set; }

    /// <summary>
    /// <para type="description">Specify a executable name to filter the list on.</para>
    /// </summary>
    [Parameter(ParameterSetName = "all", Position = 0)]
    [Parameter(Mandatory = true, ParameterSetName = "nameinfo", Position = 0)]
    public string Name { get; set; }

    /// <summary>
    /// <para type="description">Specify sub-string in the command line to filter the list on. If Name is also specified this will just select processes with that name with this sub-string.</para>
    /// </summary>
    [Parameter(ParameterSetName = "all")]
    public string CommandLine { get; set; }

    /// <summary>
    /// <para type="description">Get the process for the specified service name.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "service")]
    public string ServiceName { get; set; }

    /// <summary>
    /// <para type="description">Specify an arbitrary filter script.</para>
    /// </summary>
    [Parameter(ParameterSetName = "all")]
    public ScriptBlock FilterScript { get; set; }

    /// <summary>
    /// <para type="description">Specify access rights for each process opened.</para>
    /// </summary>
    [Parameter(ParameterSetName = "current"), 
        Parameter(ParameterSetName = "all"), 
        Parameter(ParameterSetName = "service"), 
        Parameter(ParameterSetName = "pid"),
        Parameter(ParameterSetName = "next")]
    public ProcessAccessRights Access { get; set; }

    /// <summary>
    /// <para type="description">Open current process.</para>
    /// </summary>
    [Parameter(Mandatory = true, 
        ParameterSetName = "current")]
    public SwitchParameter Current { get; set; }

    /// <summary>
    /// <para type="description">When getting all processes only get the system information process list.</para>
    /// </summary>
    [Parameter(ParameterSetName = "all")]
    public SwitchParameter FromSystem { get; set; }

    /// <summary>
    /// <para type="description">Only get process information, do not open the objects.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "infoonly"), 
        Parameter(Mandatory = true, ParameterSetName = "pidinfo"),
        Parameter(Mandatory = true, ParameterSetName = "nameinfo")]
    public SwitchParameter InfoOnly { get; set; }

    /// <summary>
    /// <para type="description">Ignore dead processes when getting process list.</para>
    /// </summary>
    [Parameter(ParameterSetName = "all")]
    public SwitchParameter IgnoreDeadProcess { get; set; }

    /// <summary>
    /// <para type="description">Return only the specified number of processes.</para>
    /// </summary>
    [Parameter(ParameterSetName = "all")]
    public int First { get; set; }

    /// <summary>
    /// <para type="description">Specify the previous process to enumerate the next process.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "next")]
    [AllowNull]
    public NtProcess NextProcess { get; set; }

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
        return proc.GetCommandLine(false).Map(s => s.ToLower().Contains(cmdline)).GetResultOrDefault();
    }

    private static bool ArbitraryFilter(NtProcess proc, ScriptBlock filter)
    {
        return filter.InvokeWithArg(false, proc);
    }

    private IEnumerable<NtObject> GetProcesses()
    {
        if (string.IsNullOrWhiteSpace(Name) 
            && string.IsNullOrWhiteSpace(CommandLine) 
            && FilterScript == null
            && !IgnoreDeadProcess
            && First <= 0)
        {
            return NtProcess.GetProcesses(Access, FromSystem);
        }

        using var procs = new DisposableList<NtProcess>(NtProcess.GetProcesses(Access, FromSystem));
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
        if (IgnoreDeadProcess)
        {
            filtered_procs = filtered_procs.Where(p => !p.IsDeleting);
        }
        if (First > 0)
        {
            filtered_procs = filtered_procs.Take(First);
        }
        return filtered_procs.Select(p => p.Duplicate()).ToArray();
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

    private NtProcess OpenSpecificProcess(ProcessAccessRights desired_access)
    {
        return Current ? GetCurrentProcess(desired_access) : NtProcess.Open(ProcessId, desired_access);
    }

    private void OpenProcess()
    {
        if (OpenParent || OpenOwner)
        {
            using NtProcess process = OpenSpecificProcess(ProcessAccessRights.QueryLimitedInformation);
            WriteObject(OpenParent ? process.OpenParent(Access) : process.OpenOwner(Access));
        }
        else
        {
            WriteObject(OpenSpecificProcess(Access));
        }
    }

    private void OpenServiceProcess()
    {
        int pid = ServiceUtils.GetServiceProcessId(ServiceName);
        if (pid == 0)
        {
            throw new ArgumentException($"Service {ServiceName} is not running");
        }
        WriteObject(NtProcess.Open(pid, Access));
    }

    private IEnumerable<NtProcessInformation> QueryProcessInformation()
    {
        var procs = NtSystemInfo.GetProcessInformationFull(false);
        if (procs.IsSuccess)
            return procs.Result;
        procs = NtSystemInfo.GetProcessInformationExtended(false);
        if (procs.IsSuccess)
            return procs.Result;
        return NtSystemInfo.GetProcessInformation();
    }

    /// <summary>
    /// Overridden ProcessRecord method.
    /// </summary>
    protected override void ProcessRecord()
    {
        switch (ParameterSetName)
        {
            case "infoonly":
                WriteObject(QueryProcessInformation(), true);
                break;
            case "all":
                WriteObject(GetProcesses(), true);
                break;
            case "pid":
            case "current":
                OpenProcess();
                break;
            case "pidinfo":
                WriteObject(QueryProcessInformation().Where(p => p.ProcessId == ProcessId), true);
                break;
            case "nameinfo":
                WriteObject(QueryProcessInformation().Where(p => p.ImageName.Equals(Name, StringComparison.CurrentCultureIgnoreCase)), true);
                break;
            case "service":
                OpenServiceProcess();
                break;
            case "next":
                WriteObject(NextProcess?.GetNextProcess(Access) ?? NtProcess.GetFirstProcess(Access));
                break;
        }
    }
}
