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
using System.IO;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Set the object ID for a file.</para>
/// <para type="description">This cmdlet sets the object ID for a file.</para>
/// </summary>
/// <example>
///   <code>Set-NtFileObjectId -File $f</code>
///   <para>Set the object ID for the file.</para>
/// </example>
/// <example>
///   <code>Set-NtFileObjectId -Path "\??\c:\windows\notepad.exe"</code>
///   <para>Set the object ID for the file by path</para>
/// </example>
/// <example>
///   <code>Set-NtFileObjectId -Path "c:\windows\notepad.exe" -Win32Path</code>
///   <para>Set the object ID for the file by win32 path</para>
/// </example>
[Cmdlet(VerbsCommon.Set, "NtFileObjectId", DefaultParameterSetName = "Default")]
public class SetNtFileObjectIdCmdlet : BaseNtFilePropertyCmdlet
{
    /// <summary>
    /// <para type="description">Specify to the object ID to set.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 1)]
    public Guid ObjectId { get; set; }

    /// <summary>
    /// <para type="description">Specify birth volume ID.</para>
    /// </summary>
    [Parameter]
    public Guid? BirthVolumeId { get; set; }

    /// <summary>
    /// <para type="description">Specify birth object ID.</para>
    /// </summary>
    [Parameter]
    public Guid? BirthObjectId { get; set; }

    /// <summary>
    /// <para type="description">Specify domain ID.</para>
    /// </summary>
    [Parameter]
    public Guid? DomainId { get; set; }

    /// <summary>
    /// <para type="description">Specify extended information.</para>
    /// </summary>
    [Parameter]
    public byte[] ExtendedInfo { get; set; }

    private byte[] BuildExtendedInfo()
    {
        if (ExtendedInfo != null)
        {
            if (ExtendedInfo.Length != 48)
                throw new ArgumentException("Extended info needs to be 48 bytes in length.");
            return ExtendedInfo;
        }

        if (BirthVolumeId.HasValue || BirthObjectId.HasValue || DomainId.HasValue)
        {
            MemoryStream stm = new();
            BinaryWriter writer = new(stm);
            writer.Write(BirthVolumeId?.ToByteArray() ?? new byte[16]);
            writer.Write(BirthObjectId?.ToByteArray() ?? new byte[16]);
            writer.Write(DomainId?.ToByteArray() ?? new byte[16]);
            return stm.ToArray();
        }

        return new byte[48];
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    public SetNtFileObjectIdCmdlet()
        : base(FileAccessRights.GenericWrite, FileShareMode.None, FileOpenOptions.None)
    {
        OpenForBackupIntent = true;
    }

    private protected override void HandleFile(NtFile file)
    {
        file.SetObjectId(ObjectId, BuildExtendedInfo());
    }
}
