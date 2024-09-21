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
using NtCoreLib.Kernel.IO;
using NtCoreLib.Security.Token;
using NtObjectManager.Utils;
using System;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Sets the reparse point buffer for file.</para>
/// <para type="description">This cmdlet sets the reparse point buffer data for a file. 
/// The absolute path to the object in the NT object manager name space can be specified.
/// To simplify calling it's also possible to specify the path in a Win32 format when using the -Win32Path parameter.</para>
/// </summary>
/// <example>
///   <code>Set-NtFileReparsePoint \??\C:\ABC \??\C:\XYZ</code>
///   <para>Sets the symbolic link for file \??\C:\ABC to point to \??\C:\XYZ.</para>
/// </example>
/// <example>
///   <code>Set-NtFileReparsePoint \??\C:\ABC \??\C:\XYZ "BLAH BLAH"</code>
///   <para>Sets the symbolic link for file \??\C:\ABC to point to \??\C:\XYZ with an explicit print name.</para>
/// </example>
/// <example>
///   <code>Set-NtFileReparsePoint \??\C:\ABC \??\C:\XYZ -Directory</code>
///   <para>Sets the symbolic link for directory \??\C:\ABC to point to \??\C:\XYZ.</para>
/// </example>
/// <example>
///   <code>Set-NtFileReparsePoint C:\ABC ..\..\XYZ -Win32Path</code>
///   <para>Sets the symbolic link for file C:\ABC to point to C:\XYZ using Win32 paths.</para>
/// </example>
/// <example>
///   <code>Set-NtFileReparsePoint \??\C:\ABC ..\..\XYZ -Relative</code>
///   <para>Sets the symbolic link for file \??\C:\ABC to point to ..\..\XYZ using a relative path.</para>
/// </example>
/// <example>
///   <code>Set-NtFileReparsePoint \??\C:\ABC \??\C:\XYZ -MountPoint</code>
///   <para>Sets the mount point for file \??\C:\ABC to point to \??\C:\XYZ.</para>
/// </example>
/// <example>
///   <code>Set-NtFileReparsePoint \??\C:\ABC -ReparseBuffer $rp</code>
///   <para>Sets the reparse buffer for file \??\C:\ABC using a raw reparse buffer.</para>
/// </example>
[Cmdlet(VerbsCommon.Set, "NtFileReparsePoint", DefaultParameterSetName = "Symlink")]
public class SetNtFileReparsePointCmdlet : NewNtFileCmdlet
{
    /// <summary>
    /// Constructor.
    /// </summary>
    public SetNtFileReparsePointCmdlet()
    {
        Access = FileAccessRights.GenericWrite;
        Disposition = FileDisposition.OpenIf;
    }

    /// <summary>
    /// <para type="description">Specify creating a mount point.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "MountPoint")]
    public SwitchParameter MountPoint { get; set; }

    /// <summary>
    /// <para type="description">Specify the target path for reparse point.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "MountPoint", Position = 1), 
        Parameter(Mandatory = true, ParameterSetName = "Symlink", Position = 1)]
    public string TargetPath { get; set; }

    /// <summary>
    /// <para type="description">Specify a print name for the reparse point.</para>
    /// </summary>
    [Parameter(ParameterSetName = "MountPoint", Position = 2),
        Parameter(ParameterSetName = "Symlink", Position = 2)]
    public string PrintName { get; set; }

    /// <summary>
    /// <para type="description">Specify the symlink target should be a relative path.</para>
    /// </summary>
    [Parameter(ParameterSetName = "Symlink")]
    public SwitchParameter Relative { get; set; }

    /// <summary>
    /// <para type="description">Specify the raw reparse point buffer.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "ReparseBuffer", Position = 1)]
    public ReparseBuffer ReparseBuffer { get; set; }

    /// <summary>
    /// <para type="description">Specify the raw reparse point buffer as bytes.</para>
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "Bytes", Position = 1)]
    public byte[] Bytes { get; set; }

    /// <summary>
    /// <para type="description">Specify an existing reparse tag to check when setting the reparse point (on RS1+).</para>
    /// </summary>
    [Parameter]
    public ReparseTag ExistingTag { get; set; }

    /// <summary>
    /// <para type="description">Specify an existing GUID to check when setting the reparse point (on RS1+).</para>
    /// </summary>
    [Parameter]
    public Guid ExistingGuid { get; set; }

    /// <summary>
    /// <para type="description">Specify flags to use when setting the reparse point (on RS1+).</para>
    /// </summary>
    [Parameter]
    public ReparseBufferExFlags Flags { get; set; }

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        NtToken.EnableEffectivePrivilege(TokenPrivilegeValue.SeCreateSymbolicLinkPrivilege);
        Options |= FileOpenOptions.OpenReparsePoint;

        if (ParameterSetName != "ReparseBuffer")
        {
            string target_path = Relative ? TargetPath : PSUtils.ResolvePath(SessionState, TargetPath, Win32Path);
            switch (ParameterSetName)
            {
                case "MountPoint":
                    Directory = true;
                    ReparseBuffer = new MountPointReparseBuffer(target_path, PrintName);
                    break;
                case "Symlink":
                    ReparseBuffer = new SymlinkReparseBuffer(target_path, string.IsNullOrEmpty(PrintName)
                        ? target_path : PrintName, Relative ? SymlinkReparseBufferFlags.Relative : SymlinkReparseBufferFlags.None);
                    break;
                case "Bytes":
                    ReparseBuffer = ReparseBuffer.FromByteArray(Bytes);
                    break;
            }
        }

        using NtFile file = (NtFile)base.CreateObject(obj_attributes);
        if (Flags != ReparseBufferExFlags.None || ExistingTag != 0 || ExistingGuid != Guid.Empty)
        {
            file.SetReparsePointEx(ReparseBuffer, Flags, ExistingTag, ExistingGuid);
        }
        else
        {
            file.SetReparsePoint(ReparseBuffer);
        }

        return null;
    }
}
