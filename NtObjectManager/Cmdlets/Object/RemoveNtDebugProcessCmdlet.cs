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
/// <para type="synopsis">Detach a process from a debug object.</para>
/// <para type="description">This cmdlet detachs a process remove a debug object.</para>
/// </summary>
/// <example>
///   <code>Remove-NtDebugProcess $dbg -ProcessId 12345</code>
///   <para>Detach process 12345 from the debug object..</para>
/// </example>
/// <example>
///   <code>Remove-NtDebugProcess $dbg -Process $proc</code>
///   <para>Detach process object from the debug object..</para>
/// </example>
[Cmdlet(VerbsCommon.Remove, "NtDebugProcess")]
public sealed class RemoveNtDebugProcessCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify the debug object to debug the process from.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    public NtDebug DebugObject { get; set; }

    /// <summary>
    /// <para type="description">Specify a process ID to detach.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "DetachPid")]
    [Alias("pid")]
    public int ProcessId { get; set; }

    /// <summary>
    /// <para type="description">Specify a process to detach.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "DetachProcess")]
    public NtProcess Process { get; set; }

    /// <summary>
    /// Overridden ProcessRecord method.
    /// </summary>
    protected override void ProcessRecord()
    {
        switch (ParameterSetName)
        {
            case "DetachPid":
                DebugObject.Detach(ProcessId);
                break;
            case "DetachProcess":
                DebugObject.Detach(Process);
                break;
        }
    }
}
