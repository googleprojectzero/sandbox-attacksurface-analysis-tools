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
/// <para type="synopsis">Get the object ID for a file.</para>
/// <para type="description">This cmdlet gets the object ID for a file.</para>
/// </summary>
/// <example>
///   <code>Get-NtFileObjectId -File $f</code>
///   <para>Get the object ID for the file.</para>
/// </example>
/// <example>
///   <code>Get-NtFileObjectId -Path "\??\c:\windows\notepad.exe"</code>
///   <para>Get the object ID for the file by path</para>
/// </example>
/// <example>
///   <code>Get-NtFileObjectId -Path "c:\windows\notepad.exe" -Win32Path</code>
///   <para>Get the object ID for the file by win32 path</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "NtFileObjectId", DefaultParameterSetName = "Default")]
[OutputType(typeof(Guid), typeof(FileObjectIdBuffer))]
public class GetNtFileObjectIdCmdlet : BaseNtFilePropertyCmdlet
{
    /// <summary>
    /// <para type="description">Specify to get extended object ID information.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter ExtendedInformation { get; set; }

    /// <summary>
    /// <para type="description">Specify to create the object ID if it doesn't already exist.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter Create { get; set; }

    /// <summary>
    /// Constructor.
    /// </summary>
    public GetNtFileObjectIdCmdlet()
        : base(FileAccessRights.Synchronize, FileShareMode.None, FileOpenOptions.None)
    {
    }

    private protected override void HandleFile(NtFile file)
    {
        var objid = Create ? file.CreateOrGetObjectId() : file.GetObjectId();
        if (ExtendedInformation)
        {
            WriteObject(objid);
        }
        else
        {
            WriteObject(objid.ObjectId);
        }
    }
}
