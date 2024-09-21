//  Copyright 2020 Google Inc. All Rights Reserved.
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
using NtObjectManager.Utils;
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Add an APC to a thread.</para>
/// <para type="description">This cmdlet queues an APC to a thread.</para>
/// </summary>
/// <example>
///   <code>Add-NtThreadApc -Thread $th -ApcRoutine $addr -Argument1 1234</code>
///   <para>Queue a thread APC for $addr.</para>
/// </example>
/// <example>
///   <code>Add-NtThreadApc -Thread $th -ApcRoutine $addr -Argument1 1234 -Special</code>
///   <para>Queue a thread special APC for $addr.</para>
/// </example>
[Cmdlet(VerbsCommon.Add, "NtThreadApc", DefaultParameterSetName = "ForApcRoutine")]
public class AddNtThreadApcCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify the thread to queue the APC to.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 0)]
    public NtThread Thread { get; set; }

    /// <summary>
    /// <para type="description">Specify the address of the APC callback.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 1, ParameterSetName = "ForApcRoutine")]
    public long ApcRoutine { get; set; }

    /// <summary>
    /// <para type="description">Specify a script block to run in the current process.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 1, ParameterSetName = "ForScriptBlock")]
    public ScriptBlock ScriptBlock { get; set; }

    /// <summary>
    /// <para type="description">Specify the first argument for the APC callback.</para>
    /// </summary>
    [Parameter(Position = 2)]
    public long Argument1 { get; set; }

    /// <summary>
    /// <para type="description">Specify the first argument for the APC callback.</para>
    /// </summary>
    [Parameter(Position = 3)]
    public long Argument2 { get; set; }

    /// <summary>
    /// <para type="description">Specify the first argument for the APC callback.</para>
    /// </summary>
    [Parameter(Position = 4)]
    public long Argument3 { get; set; }

    /// <summary>
    /// <para type="description">Specify to queue a special APC.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter Special { get; set; }

    /// <summary>
    /// Overridden ProcessRecord.
    /// </summary>
    protected override void ProcessRecord()
    {
        if (ParameterSetName == "ForScriptBlock")
        {
            if (Thread.ProcessId != NtProcess.Current.ProcessId)
                throw new ArgumentException("Must specify thread in current process to use script block.");

            ApcCallback callback = (a, b, c) => PSUtils.InvokeWithArg(ScriptBlock, a, b, c);
            if (Special)
            {
                Thread.QueueSpecialUserApc(callback, new IntPtr(Argument1), new IntPtr(Argument2), new IntPtr(Argument3));
            }
            else
            {
                Thread.QueueUserApc(callback, new IntPtr(Argument1), new IntPtr(Argument2), new IntPtr(Argument3));
            }
        }
        else
        {
            if (Special)
            {
                Thread.QueueSpecialUserApc(new IntPtr(ApcRoutine), new IntPtr(Argument1), new IntPtr(Argument2), new IntPtr(Argument3));
            }
            else
            {
                Thread.QueueUserApc(new IntPtr(ApcRoutine), new IntPtr(Argument1), new IntPtr(Argument2), new IntPtr(Argument3));
            }
        }
    }
}
