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
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Assign a process to a Job object.</para>
/// <para type="description">This cmdlet assigns a process to a Job object.</para>
/// </summary>
/// <example>
///   <code>Set-NtProcessJob -Job $job -Process $process</code>
///   <para>Assigns the process to the job object.</para>
/// </example>
/// <example>
///   <code>Set-NtProcessJob -Job $job -Current</code>
///   <para>Assigns the current process to the job object.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.Set, "NtProcessJob", DefaultParameterSetName = "FromProcess")]
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
    [Parameter(Mandatory = true, Position = 1, ValueFromPipeline = true, ParameterSetName = "FromProcess")]
    public NtProcess[] Process { get; set; }

    /// <summary>
    /// <para type="description">Specify the list of processes to assign.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "FromCurrent")]
    public SwitchParameter Current { get; set; }

    /// <summary>
    /// <para type="description">Specify to pass through the process objects.</para>
    /// </summary>
    [Parameter(ParameterSetName = "FromProcess")]
    public SwitchParameter PassThru { get; set; }

    /// <summary>
    /// Overridden ProcessRecord method.
    /// </summary>
    protected override void ProcessRecord()
    {
        if (Current)
        {
            Job.AssignProcess(NtProcess.Current);
        }
        else
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
}