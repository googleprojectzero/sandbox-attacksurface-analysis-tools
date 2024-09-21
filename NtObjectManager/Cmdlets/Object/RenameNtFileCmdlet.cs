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
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Renames a NT file object.</para>
/// <para type="description">This cmdlet renamed a NT file object. The absolute path to the object in the NT object manager name space can be specified. 
/// It's also possible to open the object relative to an existing object by specified the -Root parameter. To simply calling it's also possible to specify the
/// path in a Win32 format when using the -Win32Path parameter.</para>
/// </summary>
/// <example>
///   <code>Rename-NtFile \??\C:\path\file.exe -NewName \??\c:\newpath\file.exe</code>
///   <para>Rename a file object with an absolute path.</para>
/// </example>
/// <example>
///   <code>Rename-NtFile \??\C:\path\file.exe -NewName \??\c:\newpath\file.exe -Link</code>
///   <para>Create a link to a file object with an absolute path.</para>
/// </example>
/// <example>
///   <code>Rename-NtFile c:\path\file.exe -Win32Path -NewName c:\newpath\file.exe -ResolveNewName</code>
///   <para>Rename a file object with an absolute win32 path.</para>
/// </example>
[Cmdlet(VerbsCommon.Rename, "NtFile")]
public class RenameNtFileCmdlet : GetNtFileCmdlet
{
    /// <summary>
    /// Constructor.
    /// </summary>
    public RenameNtFileCmdlet()
    {
        Access = FileAccessRights.None;
    }

    /// <summary>
    /// <para type="description">Specify to create a link rather than do the rename.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter Link { get; set; }

    /// <summary>
    /// <para type="description">Specify to create a link rather than do the rename.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 1)]
    public string NewName { get; set; }

    /// <summary>
    /// <para type="description">Specify a root object for the new name. This is passed verbatim to the system call unless ResolveNewName is used.</para>
    /// </summary>
    [Parameter]
    public NtObject NewNameRoot { get; set; }

    /// <summary>
    /// <para type="description">Specify to resolve the new name to a full path based on win32 rules, otherwise it's passed verbatim.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter ResolveNewName { get; set; }

    /// <summary>
    /// <para type="description">Specify arbitrary flags for the rename EX setting.</para>
    /// </summary>
    [Parameter]
    public FileRenameInformationExFlags RenameFlags { get; set; }

    /// <summary>
    /// <para type="description">Replace the file if it exists.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter ReplaceIfExists { get; set; }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        FileAccessRights access = Access;
        if (Link)
        {
            if (access == FileAccessRights.None)
                access = FileAccessRights.ReadAttributes;
        }
        else
        {
            access |= FileAccessRights.Delete;
        }

        string target = ResolveNewName ? PSUtils.ResolveWin32Path(SessionState, NewName) : NewName;
        using var file = NtFile.Open(obj_attributes, access, ShareMode, Options);
        if (RenameFlags != 0)
        {
            if (ReplaceIfExists)
                RenameFlags |= FileRenameInformationExFlags.ReplaceIfExists;
            if (Link)
                file.CreateHardlinkEx(target, NewNameRoot, RenameFlags);
            else
                file.RenameEx(target, NewNameRoot, RenameFlags);
        }
        else
        {
            if (Link)
                file.CreateHardlink(target, NewNameRoot, ReplaceIfExists);
            else
                file.Rename(target, NewNameRoot, ReplaceIfExists);
        }
        return null;
    }
}
