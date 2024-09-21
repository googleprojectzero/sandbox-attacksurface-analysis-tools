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
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Gets the accessible Job objects assigned to a process.</para>
/// <para type="description">This cmdlet gets the accessible Job objects for a process. This might not include all Jobs and might contain duplicates.</para>
/// </summary>
/// <example>
///   <code>Get-NtProcessJob -Process $process</code>
///   <para>Gets the Job objects assigned to the process.</para>
/// </example>
/// <example>
///   <code>Get-NtProcessJob -Process $process -Silo</code>
///   <para>Gets the silo Job objects assigned to the process.</para>
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
    /// <para type="description">Specify to only return Silo objects.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter Silo { get; set; }

    /// <summary>
    /// Overridden ProcessRecord method.
    /// </summary>
    protected override void ProcessRecord()
    {
        if (!Silo)
        {
            WriteObject(Process.GetAccessibleJobObjects(), true);
        }
        else
        {
            using var jobs = Process.GetAccessibleJobObjects().ToDisposableList();
            WriteObject(jobs.Where(j => j.Silo).Select(j => j.Duplicate()), true);
        }
    }
}