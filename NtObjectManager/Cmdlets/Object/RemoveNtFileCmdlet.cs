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
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Deletes a NT file object.</para>
/// <para type="description">This cmdlet deletes a NT file object. The absolute path to the object in the NT object manager name space can be specified. 
/// It's also possible to open the object relative to an existing object by specified the -Root parameter. To simply calling it's also possible to specify the
/// path in a Win32 format when using the -Win32Path parameter.</para>
/// </summary>
/// <example>
///   <code>Remove-NtFile \??\C:\path\file.exe</code>
///   <para>Delete a file object with an absolute path.</para>
/// </example>
/// <example>
///   <code>$root = Get-NtFile \??\C:\path&#x0A;Remove-NtFile file.exe -Root $root</code>
///   <para>Delete a file object with a relative path.</para>
/// </example>
/// <example>
///   <code>Remove-NtFile c:\path\file.exe -Win32Path</code>
///   <para>Delete a file object with an absolute win32 path.</para>
/// </example>
/// <example>
///   <code>Remove-NtFile ..\..\..\path\file.exe -Win32Path</code>
///   <para>Delete a file object with a relative win32 path.</para>
/// </example>
/// <example>
///   <code>Remove-NtFile \??\C:\path\file.exe -PosixSemantics</code>
///   <para>Delete a file object with POSIX semantics (needs Win10 RS3+).</para>
/// </example>
/// <example>
///   <code>Remove-NtFile \??\C:\path\file.exe -DeleteReparsePoint</code>
///   <para>Delete a file reparse point rather than following the link.</para>
/// </example>
/// <example>
///   <code>Remove-NtFile \??\C:\path\file.exe -ShareMode Read</code>
///   <para>Delete a file object specifying a Read sharemode.</para>
/// </example>
[Cmdlet(VerbsCommon.Remove, "NtFile")]
public class RemoveNtFileCmdlet : GetNtFileCmdlet
{
    /// <summary>
    /// Constructor.
    /// </summary>
    public RemoveNtFileCmdlet()
    {
        Access = FileAccessRights.Delete;
        ShareMode = FileShareMode.Read | FileShareMode.Delete;
    }

    /// <summary>
    /// <para type="description">Specify whether to delete with POSIX semantics.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter PosixSemantics
    {
        get => DispositionFlags.HasFlag(FileDispositionInformationExFlags.PosixSemantics);
        set
        {
            if (value)
            {
                DispositionFlags |= FileDispositionInformationExFlags.PosixSemantics;
            }
            else
            {
                DispositionFlags &= ~FileDispositionInformationExFlags.PosixSemantics;
            }
        }
    }

    /// <summary>
    /// <para type="description">Specify whether to delete the reparse point or the target.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter DeleteReparsePoint { get; set; }

    /// <summary>
    /// <para type="description">Specify arbitrary flags for the disposition EX setting.</para>
    /// </summary>
    [Parameter]
    public FileDispositionInformationExFlags DispositionFlags { get; set; }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        using var file = NtFile.Open(obj_attributes, FileAccessRights.Delete | Access, ShareMode,
            Options | (DeleteReparsePoint ? FileOpenOptions.OpenReparsePoint : FileOpenOptions.None));
        if (DispositionFlags != 0)
        {
            file.DeleteEx(DispositionFlags | FileDispositionInformationExFlags.Delete);
        }
        else
        {
            file.Delete();
        }
        return null;
    }
}
