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
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Get the accessible children of an object directory.</para>
/// <para type="description">This cmdlet gets the children of a directory object.
///  It allows the children to be extracted recursively. You can choose to get the children through the pipeline or specify a vistor script.
/// </para>
/// </summary>
/// <example>
///   <code>$ds = Get-NtDirectoryChild $dir</code>
///   <para>Get immediate children of an object directory.</para>
/// </example>
/// <example>
///   <code>$ds = Get-NtDirectoryChild $dir -Recurse</code>
///   <para>Get children of an object directory recursively.</para>
/// </example>
/// <example>
///   <code>$ds = Get-NtDirectoryChild $dir -Recurse -MaxDepth 2</code>
///   <para>Get children of an object directory recursively up to a maximum depth of 2.</para>
/// </example>
/// <example>
///   <code>$ds = Get-NtDirectoryChild $dir Access ReadControl</code>
///   <para>Get children of an object directory which can be opened for ReadControl access.</para>
/// </example>
/// <example>
///   <code>Get-NtDirectoryChild $dir -Visitor { $path = $_.FullPath; Write-Host $path }</code>
///   <para>Get children of an object directory via the visitor pattern.</para>
/// </example>
/// <example>
///   <code>Get-NtDirectoryChild $dir -Recurse -Visitor { $path = $_.FullPath; Write-Host $path; $path -notmatch "BLAH" }</code>
///   <para>Get children of an object directory via the visitor pattern, exiting the recursion if the object path contains the string BLAH.</para>
/// </example>
/// <example>
///   <code>$ds = Get-NtDirectoryChild $dir -Recurse -Filter { $_.FullPath -match "BLAH" }</code>
///   <para>Get children of an object directory filtering out any objects which don't have BLAH in the name.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.Get, "NtDirectoryChild")]
public class GetNtDirectoryChildCmdlet : BaseGetNtChildObjectCmdlet<NtDirectory, DirectoryAccessRights>
{
    /// <summary>
    /// Overridden visit method.
    /// </summary>
    /// <param name="visitor">The visitor function.</param>
    /// <returns>Returns true if visited all children.</returns>
    protected override bool VisitChildObjects(Func<NtDirectory, bool> visitor)
    {
        return Object.VisitAccessibleDirectories(visitor, Access, Recurse, MaxDepth);
    }
}
