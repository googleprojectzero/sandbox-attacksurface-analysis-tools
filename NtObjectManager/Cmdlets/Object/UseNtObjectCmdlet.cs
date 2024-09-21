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

using NtObjectManager.Utils;
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Use an NtObject (or list of NtObject) and automatically close the objects after use.</para>
/// <para type="description">This cmdlet allows you to scope the use of NtObject, similar to the using statement in C#.
/// When the script block passed to this cmdlet goes out of scope the input object is automatically disposed of, ensuring
/// any native resources are closed to prevent leaks.
/// </para>
/// </summary>
/// <example>
///   <code>$ps = Use-NtObject (Get-NtProcess) { param ($ps); $ps | Select-Object Name, CommandLine }</code>
///   <para>Select Name and CommandLine from a list of processes and dispose of the list afterwards.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsOther.Use, "NtObject")]
public sealed class UseNtObjectCmdlet : Cmdlet, IDisposable
{
    /// <summary>
    /// <para type="description">Specify the input object to be disposed.</para>
    /// </summary>
    [Parameter(Mandatory = true, ValueFromPipeline = true, Position = 0)]
    [AllowNull]
    public object InputObject { get; set; }

    /// <summary>
    /// <para type="description">Specify the script block to execute.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 1)]
    public ScriptBlock ScriptBlock { get; set; }

    /// <summary>
    /// Overridden process record method
    /// </summary>
    protected override void ProcessRecord()
    {
        WriteObject(ScriptBlock.InvokeWithArg(InputObject), true);
    }

    void IDisposable.Dispose()
    {
        PSUtils.Dispose(InputObject);
    }
}
