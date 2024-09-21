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
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Get the list of processes which are sharing this file.</para>
/// <para type="description">This cmdlet gets the list of processes which are sharing this file.</para>
/// </summary>
/// <example>
///   <code>Get-NtFileShareProcess -File $f</code>
///   <para>Get the sharing processes for the file.</para>
/// </example>
/// <example>
///   <code>Get-NtFileShareProcess -Path "\??\C:\windows\system32\kernel32.dll"</code>
///   <para>Get the sharing processes for kernel32.dll.</para>
/// </example>
/// <example>
///   <code>Get-NtFileShareProcess -Path "C:\windows\system32\kernel32.dll" -Win32Path</code>
///   <para>Get the sharing processes for kernel32.dll.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "NtFileShareProcess", DefaultParameterSetName = "Default")]
[OutputType(typeof(NtProcessInformation))]
public class GetNtFileShareProcessCmdlet : BaseNtFilePropertyCmdlet
{
    /// <summary>
    /// Constructor.
    /// </summary>
    public GetNtFileShareProcessCmdlet()
        : base(FileAccessRights.ReadAttributes, FileShareMode.None, FileOpenOptions.None)
    {
    }

    private protected override void HandleFile(NtFile file)
    {
        var pids = new HashSet<int>(file.GetUsingProcessIds());

        WriteObject(NtSystemInfo.GetProcessInformationExtended().Where(p => pids.Contains(p.ProcessId)), true);
    }
}
