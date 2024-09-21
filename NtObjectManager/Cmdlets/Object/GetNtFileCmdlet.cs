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
using NtCoreLib.Win32.Device;
using NtObjectManager.Utils;
using System;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Open a existing NT file object.</para>
/// <para type="description">This cmdlet opens a existing NT file object. The absolute path to the object in the NT object manager name space can be specified. 
/// It's also possible to open the object relative to an existing object by specified the -Root parameter. To simply calling it's also possible to specify the
/// path in a Win32 format when using the -Win32Path parameter.</para>
/// </summary>
/// <example>
///   <code>$obj = Get-NtFile \??\C:\Windows\Notepad.exe</code>
///   <para>Open a file object with an absolute path.</para>
/// </example>
/// <example>
///   <code>$root = Get-NtFile \??\C:\Windows&#x0A;$obj = Get-NtFile Notepad.exe -Root $root</code>
///   <para>Open a file object with a relative path.</para>
/// </example>
/// <example>
///   <code>$obj = Get-NtFile c:\Windows\Notepad.exe -Win32Path</code>
///   <para>Open a file object with an absolute win32 path.</para>
/// </example>
/// <example>
///   <code>$obj = Get-NtFile ..\..\..\Windows\Notepad.exe -Win32Path</code>
///   <para>Open a file object with a relative win32 path.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.Get, "NtFile")]
[OutputType(typeof(NtFile))]
public class GetNtFileCmdlet : NtObjectBaseCmdletWithAccess<FileAccessRights>
{
    /// <summary>
    /// <para type="description">The NT object manager path to the object to use.</para>
    /// </summary>
    [Parameter(Position = 0, Mandatory = true)]
    [AllowEmptyString]
    public override string Path { get; set; }

    /// <summary>
    /// <para type="description">Specify that the path is a device GUID not a full path.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter DeviceGuid { get; set; }

    /// <summary>
    /// <para type="description">Specify the path is a file id, in string format (e.g. 12345678) or a GUID object id.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter OpenById { get; set; }

    /// <summary>
    /// Determine if the cmdlet can create objects.
    /// </summary>
    /// <returns>True if objects can be created.</returns>
    protected override bool CanCreateDirectories()
    {
        return false;
    }

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
    /// <para type="description">The access share mode to open the file with.</para>
    /// </summary>
    [Parameter]
    public FileShareMode ShareMode { get; set; }

    /// <summary>
    /// <para type="description">The options to open the file with.</para>
    /// </summary>
    [Parameter]
    public FileOpenOptions Options { get; set; }

    /// <summary>
    /// <para type="description">Specify a transaction to create the file under.</para>
    /// </summary>
    [Parameter]
    public NtTransaction Transaction { get; set; }

    /// <summary>
    /// Get the Win32 path for a specified path.
    /// </summary>
    /// <param name="path">The path component.</param>
    /// <returns>The full NT path.</returns>
    protected override string GetWin32Path(string path)
    {
        return PSUtils.ResolvePath(SessionState, Path, true);
    }

    /// <summary>
    /// Get the base object manager path for the current powershell directory.
    /// </summary>
    /// <returns>The base path.</returns>
    protected override NtResult<string> GetBasePath()
    {
        var result = base.GetBasePath();
        if (result.IsSuccess)
            return result;
        return PSUtils.GetFileBasePath(SessionState);
    }

    /// <summary>
    /// Virtual method to resolve the value of the Path variable.
    /// </summary>
    /// <returns>The object path.</returns>
    protected override string ResolvePath()
    {
        if (DeviceGuid)
        {
            string path = DeviceUtils.GetDeviceInterfaceList(new Guid(Path)).FirstOrDefault();
            if (path == null)
            {
                throw new ArgumentException($"No device paths for interface {Path}");
            }
            return NtFileUtils.DosFileNameToNt(path);
        }
        else if (OpenById)
        {
            byte[] data;
            if (Guid.TryParse(Path, out Guid object_id))
            {
                data = object_id.ToByteArray();
            }
            else
            {
                data = BitConverter.GetBytes(long.Parse(Path));
            }
            
            return Convert.ToBase64String(data);
        }

        return base.ResolvePath();
    }

    /// <summary>
    /// Indicates that the path is raw and should be passed through Base64 decode.
    /// </summary>
    protected override bool IsRawPath => OpenById;

    /// <summary>
    /// Method to create an object from a set of object attributes.
    /// </summary>
    /// <param name="obj_attributes">The object attributes to create/open from.</param>
    /// <returns>The newly created object.</returns>
    protected override object CreateObject(ObjectAttributes obj_attributes)
    {
        using (Transaction?.Enable())
        {
            FileOpenOptions opts = Options;
            if (OpenById)
                opts |= FileOpenOptions.OpenByFileId;
            return NtFile.Open(obj_attributes, Access, ShareMode, opts);
        }
    }
}
