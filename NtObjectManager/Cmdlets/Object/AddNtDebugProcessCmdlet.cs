//  Copyright 2019 Google Inc. All Rights Reserved.
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
/// <para type="synopsis">Attach a process to a debug object.</para>
/// <para type="description">This cmdlet attaches a process to a debug object. You can remove it again using
/// Remove-NtDebugProcess.</para>
/// </summary>
/// <example>
///   <code>Add-NtDebugProcess $dbg -ProcessId 12345</code>
///   <para>Attach process 12345 to the debug object..</para>
/// </example>
/// <example>
///   <code>Add-NtDebugProcess $dbg -Process $proc</code>
///   <para>Attach a process object to the debug object..</para>
/// </example>
[Cmdlet(VerbsCommon.Add, "NtDebugProcess")]
public sealed class AddNtDebugProcessCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify the debug object to attach the process to.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public NtDebug DebugObject { get; set; }

    /// <summary>
    /// <para type="description">Specify a process ID to attach to .</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "AttachPid")]
    [Alias("pid")]
    public int ProcessId { get; set; }

    /// <summary>
    /// <para type="description">Specify a process to attach to.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "AttachProcess")]
    public NtProcess Process { get; set; }

    /// <summary>
    /// Overridden ProcessRecord method.
    /// </summary>
    protected override void ProcessRecord()
    {
        switch (ParameterSetName)
        {
            case "AttachPid":
                DebugObject.Attach(ProcessId);
                break;
            case "AttachProcess":
                DebugObject.Attach(Process);
                break;
        }
    }
}
