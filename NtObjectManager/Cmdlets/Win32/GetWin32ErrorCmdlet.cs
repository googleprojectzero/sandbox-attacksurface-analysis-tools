//  Copyright 2018 Google Inc. All Rights Reserved.
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

using NtCoreLib.Win32;
using System;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Win32;

/// <summary>
/// <para type="synopsis">Get known information about a WIN32 error code.</para>
/// <para type="description">This cmdlet looks up an WIN32 error code and if possible prints the
/// enumeration name and the message description.
/// </para>
/// </summary>
/// <example>
///   <code>Get-Win32Error</code>
///   <para>Gets all known WIN32 error codes defined in this library.</para>
/// </example>
/// <example>
///   <code>Get-Win32Error -Error 5</code>
///   <para>Gets information about a specific WIN32 error code.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "Win32Error", DefaultParameterSetName = "All")]
public sealed class GetWin32ErrorCmdlet : PSCmdlet
{
    /// <summary>
    /// <para type="description">Specify a WIN32 error code to retrieve.</para>
    /// </summary>
    [Parameter(Position = 0, ParameterSetName = "FromError")]
    public int Error { get; set; }

    /// <summary>
    /// Process record.
    /// </summary>
    protected override void ProcessRecord()
    {
        if (ParameterSetName == "FromError")
        {
            WriteObject(new Win32ErrorResult((Win32Error)Error));
        }
        else
        {
            WriteObject(Enum.GetValues(typeof(Win32Error)).Cast<Win32Error>()
                .Distinct().Select(e => new Win32ErrorResult(e)), true);
        }
    }
}
