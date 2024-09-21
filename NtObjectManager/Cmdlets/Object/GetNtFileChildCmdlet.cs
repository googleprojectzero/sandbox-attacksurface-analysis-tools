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
using NtCoreLib.Security.Token;
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Get the accessible children of a file directory.</para>
/// <para type="description">This cmdlet gets the children of a file directory object.
///  It allows the children to be extracted recursively. You can choose to get the children through the pipeline or specify a vistor script.
/// </para>
/// </summary>
/// <example>
///   <code>$files = Get-NtFileChild $file</code>
///   <para>Get immediate children of a file directory.</para>
/// </example>
/// <example>
///   <code>$files = Get-NtFileChild $file -Streams</code>
///   <para>Get immediate children and any streams of a file.</para>
/// </example>
/// <example>
///   <code>$files = Get-NtFileChild $file -Recurse</code>
///   <para>Get children of a file directory recursively.</para>
/// </example>
/// <example>
///   <code>$files = Get-NtFileChild $file -Recurse -OpenForBackup</code>
///   <para>Get children of a file directory recursively.</para>
/// </example>
/// <example>
///   <code>$files = Get-NtFileChild $file -Recurse -MaxDepth 2</code>
///   <para>Get children of a file directory recursively up to a maximum depth of 2.</para>
/// </example>
/// <example>
///   <code>$files = Get-NtFileChild $file -Recurse -FileMask *.txt</code>
///   <para>Get children of a file directory recursively, only returning files which match the pattern *.txt.</para>
/// </example>
/// <example>
///   <code>$files = Get-NtFileChild $file -Recurse -TypeMask DirectoriesOnly</code>
///   <para>Get children of a file directory recursively, only returning directories.</para>
/// </example>
/// <example>
///   <code>$files = Get-NtFileChild $file Access ReadControl</code>
///   <para>Get children of a file directory which can be opened for ReadControl access.</para>
/// </example>
/// <example>
///   <code>Get-NtFileChild $file -Visitor { $path = $_.FullPath; Write-Host $path }</code>
///   <para>Get children of a file directory via the visitor pattern.</para>
/// </example>
/// <example>
///   <code>Get-NtFileChild $file -Recurse -Visitor { $path = $_.FullPath; Write-Host $path; $path -notmatch "BLAH" }</code>
///   <para>Get children of a file directory via the visitor pattern, exiting the recursion if the object path contains the string BLAH.</para>
/// </example>
/// <example>
///   <code>$files = Get-NtFileChild $file -Recurse -Filter { $_.FullPath -match "BLAH" }</code>
///   <para>Get children of a file directory filtering out any objects which don't have BLAH in the name.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.Get, "NtFileChild")]
public class GetNtFileChildCmdlet : BaseGetNtChildObjectCmdlet<NtFile, FileAccessRights>
{
    /// <summary>
    /// Constructor.
    /// </summary>
    public GetNtFileChildCmdlet()
    {
        // Specify a simple default to allow reading security descriptor and attributes.
        Access = FileAccessRights.ReadControl | FileAccessRights.ReadAttributes;
        FileMask = "*";
    }

    /// <summary>
    /// Overridden BeginProcessing.
    /// </summary>
    protected override void BeginProcessing()
    {
        if (OpenForBackup)
        {
            using var token = NtToken.OpenEffectiveToken();
            if (!token.SetPrivilege(TokenPrivilegeValue.SeBackupPrivilege, PrivilegeAttributes.Enabled))
            {
                WriteWarning("OpenForBackup specified but caller doesn't have SeBackupPrivilege");
            }
        }
        base.BeginProcessing();
    }

    /// <summary>
    /// <para type="description">Open keys for backup. Needs SeBackupPrivilege enabled.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter OpenForBackup { get; set; }

    /// <summary>
    /// <para type="description">Get named streams of files as well as children.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter Streams { get; set; }

    /// <summary>
    /// <para type="description">Specify file access using directory access rights.</para>
    /// </summary>
    [Parameter]
    public FileDirectoryAccessRights DirectoryAccess
    {
        get => Access.ToDirectoryAccessRights();
        set => Access = value.ToFileAccessRights();
    }

    /// <summary>
    /// <para type="description">The access share mode to open the files with.</para>
    /// </summary>
    [Parameter]
    public FileShareMode ShareMode { get; set; }

    /// <summary>
    /// <para type="description">Specify a filter name filter such as *.txt.</para>
    /// </summary>
    [Parameter]
    public string FileMask { get; set; }

    /// <summary>
    /// <para type="description">Specify the types of files to return.</para>
    /// </summary>
    [Parameter]
    public FileTypeMask TypeMask { get; set; }

    private bool VisitStreams(NtFile file, FileOpenOptions options, Func<NtFile, bool> visitor)
    {
        return file.VisitAccessibleStreams(visitor, Access, ShareMode, options);
    }

    /// <summary>
    /// Overridden visit method.
    /// </summary>
    /// <param name="visitor">The visitor function.</param>
    /// <returns>Returns true if visited all children.</returns>
    protected override bool VisitChildObjects(Func<NtFile, bool> visitor)
    {
        bool read_attributes = Object.IsAccessGranted(FileAccessRights.ReadAttributes);
        if (!read_attributes)
        {
            WriteWarning("File object does not have ReadAttributes access. Getting children might not work as expected");
        }

        FileOpenOptions options = FileOpenOptions.OpenReparsePoint;
        if (OpenForBackup)
        {
            options |= FileOpenOptions.OpenForBackupIntent;
        }

        if (!read_attributes || Object.IsDirectory)
        {
            if (!Object.IsAccessGranted(FileDirectoryAccessRights.ListDirectory))
            {
                WriteWarning("File object does not have ListDirectory access. Getting children might not work as expected");
            }

            Func<NtFile, bool> new_visitor = visitor;

            if (Streams)
            {
                new_visitor = o =>
                {
                    bool result = visitor(o);
                    if (result)
                    {
                        result = VisitStreams(o, options, visitor);
                    }
                    return result;
                };
            }

            return Object.VisitAccessibleFiles(new_visitor, Access, ShareMode, options, Recurse, MaxDepth, FileMask, TypeMask);
        }
        else if (Streams)
        {
            return VisitStreams(Object, options, visitor);
        }
        else
        {
            throw new ArgumentException("Must specify a directory file object");
        }
    }
}
