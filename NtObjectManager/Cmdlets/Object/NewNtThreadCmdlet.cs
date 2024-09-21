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
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Create a new thread.</para>
/// <para type="description">This cmdlet creates a new thread in a specified process.</para>
/// </summary>
/// <example>
///   <code>$thread = New-NtThread -StartRoutine 0x12345678</code>
///   <para>Create a new thread with a specified start routine address in the current process.</para>
/// </example>
/// <example>
///   <code>$thread = New-NtThread -StartRoutine 0x12345678 -Argument 0x9ABCEDF</code>
///   <para>Create a new thread with a specified start routine address and argument in the current process.</para>
/// </example>
/// <example>
///   <code>$thread = New-NtThread -StartRoutine 0x12345678 -Process $proc</code>
///   <para>Create a new thread with a specified start routine address in another process.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.New, "NtThread")]
[OutputType(typeof(NtThread))]
public class NewNtThreadCmdlet : NtObjectBaseCmdletWithAccess<ThreadAccessRights>
{
    /// <summary>
    /// <para type="description">Specify start address.</para>
    /// </summary>
    [Parameter(Mandatory = true)]
    public IntPtr StartRoutine { get; set; }

    /// <summary>
    /// <para type="description">Specify the process to start the thread in.</para>
    /// </summary>
    [Parameter]
    public NtProcess Process { get; set; }

    /// <summary>
    /// <para type="description">Specify initial argument for the thread.</para>
    /// </summary>
    [Parameter]
    public IntPtr Argument { get; set; }

    /// <summary>
    /// <para type="description">Specify create flags for the thread.</para>
    /// </summary>
    [Parameter]
    public ThreadCreateFlags CreateFlags { get; set; }

    /// <summary>
    /// <para type="description">Specify zero bits for the stack.</para>
    /// </summary>
    [Parameter]
    public IntPtr ZeroBits { get; set; }

    /// <summary>
    /// <para type="description">Specify initial stack size.</para>
    /// </summary>
    [Parameter]
    public IntPtr StackSize { get; set; }

    /// <summary>
    /// <para type="description">Specify maximum stack size.</para>
    /// </summary>
    [Parameter]
    public IntPtr MaximumStackSize { get; set; }

    /// <summary>
    /// Determine if the cmdlet can create objects.
    /// </summary>
    /// <returns>True if objects can be created.</returns>
    protected override bool CanCreateDirectories()
    {
        return false;
    }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        NtProcess process = Process ?? NtProcess.Current;
        return NtThread.Create(obj_attributes, Access, process, StartRoutine.ToInt64(), Argument.ToInt64(),
            CreateFlags, ZeroBits.ToInt64(), StackSize.ToInt64(), MaximumStackSize.ToInt64(), null);
    }
}
