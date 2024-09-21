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
using NtCoreLib.Security.Authorization;
using NtObjectManager.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="description">Handle group.</para>
/// </summary>
public sealed class NtHandleObjectGroup 
{
    private readonly Lazy<Tuple<string, SecurityDescriptor>> _get_values;

    private Tuple<string, SecurityDescriptor> GetValues()
    {
        string name = null;
        SecurityDescriptor sd = null;
        foreach (var h in Handles)
        {
            if (h.HandleValid)
            {
                if (name == null)
                {
                    name = h.Name;
                }
                if (sd == null)
                {
                    sd = h.SecurityDescriptor;
                }
                if (name != null && sd != null)
                {
                    break;
                }
            }
        }
        return Tuple.Create(name ?? string.Empty, sd);
    }

    /// <summary>
    /// The mumber of handles in the group.
    /// </summary>
    public long Count { get; }
    /// <summary>
    /// Number of processes this kernel object is shared with.
    /// </summary>
    public int ShareCount { get; }
    /// <summary>
    /// The list of unique process IDs.
    /// </summary>
    public IEnumerable<int> ProcessIds { get; }
    /// <summary>
    /// The name of the key.
    /// </summary>
    public ulong Object { get; }
    /// <summary>
    /// The group enumeration.
    /// </summary>
    public IEnumerable<NtHandle> Handles { get; }
    /// <summary>
    /// Get the security descriptor for the handle group.
    /// </summary>
    public SecurityDescriptor SecurityDescriptor => _get_values.Value.Item2;
    /// <summary>
    /// Get the name for the handle group.
    /// </summary>
    public string Name => _get_values.Value.Item1;
    /// <summary>
    /// Does the group have a name.
    /// </summary>
    public bool HasName => Name.Length > 0;
    /// <summary>
    /// Does the group have a security descriptor.
    /// </summary>
    public bool HasSecurityDescriptor => SecurityDescriptor != null;
    /// <summary>
    /// The intersection of all handle access.
    /// </summary>
    public AccessMask AccessIntersection { get; }
    /// <summary>
    /// The union of all handle access.
    /// </summary>
    public AccessMask AccessUnion { get; }

    private static AccessMask IntersectAccessMask(IEnumerable<IGrouping<int, NtHandle>> pid_group)
    {
        AccessMask start_mask = 0xFFFFFFFF;
        foreach (var group in pid_group)
        {
            AccessMask curr_mask = group.Select(h => h.GrantedAccess).Aggregate((a, b) => a | b);
            start_mask &= curr_mask;
        }
        return start_mask;
    }

    internal NtHandleObjectGroup(IGrouping<ulong, NtHandle> group)
    {
        Object = group.Key;
        Count = group.Count();
        Handles = group;
        var pid_group = group.GroupBy(h => h.ProcessId);
        var pids = pid_group.Select(g => g.Key).ToList();
        ProcessIds = pids.AsReadOnly();
        ShareCount = pids.Count;
        AccessIntersection = IntersectAccessMask(pid_group);
        AccessUnion = group.Select(h => h.GrantedAccess).Aggregate((a, b) => a | b);
        _get_values = new Lazy<Tuple<string, SecurityDescriptor>>(GetValues);
    }
}

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
///   <code>Get-NtHandle -Process $p</code>
///   <para>Get all NT handles for a process.</para>
/// </example>
/// <example>
///   <code>Get-NtHandle 1234 -NoQuery</code>
///   <para>Get all NT handles filtered to a specific Process ID but don't try and query information about the handle such as name.</para>
/// </example>
///     /// <example>
///   <code>Get-NtHandle -GroupByAddress</code>
///   <para>Get all NT handles grouped by their object address.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "NtHandle", DefaultParameterSetName = "All")]
[OutputType(typeof(NtHandle), typeof(NtHandleObjectGroup))]
public class GetNtHandleCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify a process ID to filter handles on.</para>
    /// </summary>
    [Parameter(Position = 0, ParameterSetName = "FromPid")]
    [Alias(new string[] { "pid" })]
    public int ProcessId { get; set; }

    /// <summary>
    /// <para type="description">Specify a process to query handles for.</para>
    /// </summary>
    [Parameter(Position = 0, ParameterSetName = "FromProcess")]
    public NtProcess Process { get; set; }

    /// <summary>
    /// <para type="description">Specify that the returned handle entries should not be queried for additional information.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter NoQuery { get; set; }

    /// <summary>
    /// <para type="description">Specify that the returned handle entries should force querying for file information from non-filesystem files. 
    /// This is not the default as it can cause the lookup of filenames and security descriptors to hang.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter ForceFileQuery { get; set; }

    /// <summary>
    /// <para type="description">Specify list of object types to filter handles.</para>
    /// </summary>
    [Parameter, ArgumentCompleter(typeof(NtTypeArgumentCompleter))]
    [Alias("ObjectTypes")]
    public string[] ObjectType { get; set; }

    /// <summary>
    /// <para type="description">Specify the result should be grouped by address.</para>
    /// </summary>
    [Parameter(ParameterSetName = "All")]
    public SwitchParameter GroupByAddress { get; set; }

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
        IEnumerable<NtHandle> handles;
        if (ParameterSetName == "FromProcess")
        {
            handles = Process.GetHandles(!NoQuery, ForceFileQuery, true).Result;
        }
        else
        {
            handles = NtSystemInfo.GetHandles(ProcessId, !NoQuery, ForceFileQuery);
        }

        if (ObjectType?.Length > 0)
        {
            HashSet<string> object_types = new(ObjectType, StringComparer.OrdinalIgnoreCase);
            handles = handles.Where(h => object_types.Contains(h.ObjectType));
        }

        if (GroupByAddress)
        {
            WriteObject(handles.GroupBy(h => h.Object).Select(g => new NtHandleObjectGroup(g)), true);
        }
        else
        {
            WriteObject(handles, true);
        }
    }
}
