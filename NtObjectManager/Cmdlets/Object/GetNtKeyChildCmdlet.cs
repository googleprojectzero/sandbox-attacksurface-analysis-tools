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
/// <para type="synopsis">Get the accessible children of a key.</para>
/// <para type="description">This cmdlet gets the children of a key object.
///  It allows the children to be extracted recursively. You can choose to get the children through the pipeline or specify a vistor script.
/// </para>
/// </summary>
/// <example>
///   <code>$keys = Get-NtKeyChild $key</code>
///   <para>Get immediate children of a key.</para>
/// </example>
/// <example>
///   <code>$keys = Get-NtKeyChild $key -Recurse</code>
///   <para>Get children of a key recursively.</para>
/// </example>
/// <example>
///   <code>$keys = Get-NtKeyChild $key -Recurse -OpenForBackup</code>
///   <para>Get children of a key recursively.</para>
/// </example>
/// <example>
///   <code>$keys = Get-NtKeyChild $key -Recurse -MaxDepth 2</code>
///   <para>Get children of a key recursively up to a maximum depth of 2.</para>
/// </example>
/// <example>
///   <code>$keys = Get-NtKeyChild $key Access ReadControl</code>
///   <para>Get children of a key which can be opened for ReadControl access.</para>
/// </example>
/// <example>
///   <code>Get-NtKeyChild $key -Visitor { $path = $_.FullPath; Write-Host $path }</code>
///   <para>Get children of a key via the visitor pattern.</para>
/// </example>
/// <example>
///   <code>Get-NtKeyChild $key -Recurse -Visitor { $path = $_.FullPath; Write-Host $path; $path -notmatch "BLAH" }</code>
///   <para>Get children of a key via the visitor pattern, exiting the recursion if the object path contains the string BLAH.</para>
/// </example>
/// <example>
///   <code>$keys = Get-NtKeyChild $key -Recurse -Filter { $_.FullPath -match "BLAH" }</code>
///   <para>Get children of a key filtering out any objects which don't have BLAH in the name.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.Get, "NtKeyChild")]
public class GetNtKeyChildCmdlet : BaseGetNtChildObjectCmdlet<NtKey, KeyAccessRights>
{
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
    /// Overridden visit method.
    /// </summary>
    /// <param name="visitor">The visitor function.</param>
    /// <returns>Returns true if visited all children.</returns>
    protected override bool VisitChildObjects(Func<NtKey, bool> visitor)
    {
        return Object.VisitAccessibleKeys(visitor, Access, OpenForBackup, Recurse, MaxDepth);
    }
}
