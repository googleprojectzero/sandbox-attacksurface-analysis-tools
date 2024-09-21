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
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

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
[Cmdlet(VerbsCommon.New, "NtJob", DefaultParameterSetName = "FromPath")]
[OutputType(typeof(NtJob))]
public sealed class NewNtJobCmdlet : NtObjectBaseCmdletWithAccess<JobAccessRights>
{
    /// <summary>
    /// <para type="description">The NT object manager path to the object to use.</para>
    /// </summary>
    [Parameter(Position = 0, ParameterSetName = "FromPath"), 
        Parameter(Position = 0, ParameterSetName = "CreateSilo"), 
        Parameter(Position = 0, ParameterSetName = "CreateServerSilo")]
    public override string Path { get => base.Path; set => base.Path = value; }

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
    /// <para type="description">Specify to create Job as a Silo.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "CreateSilo")]
    public SwitchParameter CreateSilo { get; set; }

    /// <summary>
    /// <para type="description">Specify to not create a silo root directory.</para>
    /// </summary>
    [Parameter(ParameterSetName = "CreateSilo")]
    public SwitchParameter NoSiloRootDirectory { get; set; }

    /// <summary>
    /// <para type="description">Specify to flags when creating the Silo's root directory.</para>
    /// </summary>
    [Parameter(ParameterSetName = "CreateSilo"), Parameter(ParameterSetName = "CreateServerSilo")]
    public SiloObjectRootDirectoryControlFlags SiloRootDirectoryFlags { get; set; }

    /// <summary>
    /// <para type="description">Specify to create a server silo. Must be used with -CreateSilo.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "CreateServerSilo")]
    public SwitchParameter CreateServerSilo { get; set; }

    /// <summary>
    /// <para type="description">Specify system root for the server silo.</para>
    /// </summary>
    [Parameter(ParameterSetName = "CreateServerSilo")]
    public string SystemRoot { get; set; }

    /// <summary>
    /// <para type="description">Specify event for when the silo is deleted.</para>
    /// </summary>
    [Parameter(ParameterSetName = "CreateServerSilo")]
    public NtEvent DeleteEvent { get; set; }

    /// <summary>
    /// <para type="description">Specify whether silo is a downlevel container.</para>
    /// </summary>
    [Parameter(ParameterSetName = "CreateServerSilo")]
    public SwitchParameter DownlevelContainer { get; set; }

    /// <summary>
    /// <para type="description">Specify to place a limit on process memory.</para>
    /// </summary>
    [Parameter]
    public long ProcessMemoryLimit { get; set; }

    /// <summary>
    /// <para type="description">Specify to place a limit on job memory.</para>
    /// </summary>
    [Parameter]
    public long JobMemoryLimit { get; set; }

    /// <summary>
    /// <para type="description">Specify to place a limit on job user execution time.</para>
    /// </summary>
    [Parameter]
    public NtWaitTimeout ProcessTimeLimit { get; set; }

    /// <summary>
    /// <para type="description">Specify to place a limit on job user execution time.</para>
    /// </summary>
    [Parameter]
    public NtWaitTimeout JobTimeLimit { get; set; }

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
        using var job = CreateJob(obj_attributes);
        if (LimitFlags != 0)
        {
            job.LimitFlags = LimitFlags;
        }
        if (ActiveProcessLimit > 0)
        {
            job.ActiveProcess = ActiveProcessLimit;
        }
        if (UiRestrictionFlags != 0)
        {
            job.UiRestrictionFlags = UiRestrictionFlags;
        }
        if (ProcessMemoryLimit > 0)
        {
            job.ProcessMemory = ProcessMemoryLimit;
        }
        if (JobMemoryLimit > 0)
        {
            job.JobMemory = JobMemoryLimit;
        }

        if (JobTimeLimit?.Timeout != null)
        {
            job.JobTime = JobTimeLimit.Timeout.QuadPart;
        }

        if (ProcessTimeLimit?.Timeout != null)
        {
            job.ProcessTime = ProcessTimeLimit.Timeout.QuadPart;
        }

        return job.Duplicate();
    }

    private NtJob CreateJob(ObjectAttributes obj_attributes)
    {
        if (CreateServerSilo)
        {
            return NtJob.CreateServerSilo(obj_attributes, Access, SiloRootDirectoryFlags, 
                SystemRoot ?? Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToUpper().TrimEnd('\\'), 
                DeleteEvent, DownlevelContainer);
        }
        else if (CreateSilo)
        {
            if (NoSiloRootDirectory)
            {
                using var job = NtJob.Create(obj_attributes, Access | JobAccessRights.SetAttributes);
                job.SetLimitFlags(JobObjectLimitFlags.Application);
                job.CreateSilo();
                return job.Duplicate();
            }

            return NtJob.CreateSilo(obj_attributes, Access, SiloRootDirectoryFlags);
        }

        return NtJob.Create(obj_attributes, Access);
    }
}