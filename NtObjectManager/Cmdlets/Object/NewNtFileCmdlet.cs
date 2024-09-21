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
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Create a new NT file object.</para>
/// <para type="description">This cmdlet creates a new NT file object. The absolute path to the object in the NT object manager name space can be specified. 
/// It's also possible to open the object relative to an existing object by specified the -Root parameter.</para>
/// </summary>
/// <example>
///   <code>$obj = New-NtFile \??\C:\Windows\Temp\abc.txt</code>
///   <para>Creates a new file object with an absolute path.</para>
/// </example>
/// <example>
///   <code>$obj = New-NtFile \??\C:\Windows\Temp\ABC -Directory</code>
///   <para>Creates a new directory file object with an absolute path.</para>
/// </example>
/// <example>
///   <code>$obj = New-NtFile \??\C:\Windows\Temp\abc.txt -Attributes Hidden</code>
///   <para>Creates a new file object with an absolute path, with the hidden attribute.</para>
/// </example>
/// <example>
///   <code>$root = Get-NtFile \??\C:\Windows&#x0A;$obj = New-NtFile Temp\abc.txt -Root $root</code>
///   <para>Creates a new file object with a relative path.</para>
/// </example>
/// <example>
///   <code>$obj = New-NtFile c:\Windows\Temp\abc.txt -Win32Path</code>
///   <para>Creates a new file object with an absolute win32 path.</para>
/// </example>
/// <example>
///   <code>$obj = New-NtFile \??\C:\Windows\Temp\abc.txt -Disposition OpenIf</code>
///   <para>Creates a new file object with an absolute path. If the file already exists then open it rather than failing.</para>
/// </example>
/// <example>
///   <code>$obj = New-NtFile \??\C:\Windows\Temp\abc.txt -Disposition Supersede</code>
///   <para>Creates a new file object with an absolute path. If the file already exists then replace it with the new file.</para>
/// </example>
/// <example>
///   <code>$obj = New-NtFile \??\C:\Windows\Temp\abc.txt -Options SynchronousIoNonAlert -Access GenericRead,GenericWrite,Synchronize&#x0A;$stm = $obj.ToStream($true)&#x0A;$stm.WriteByte(1)</code>
///   <para>Creates a new file object with an absolute path then writes data to it.</para>
/// </example>
/// <para type="link">about_ManagingNtObjectLifetime</para>
[Cmdlet(VerbsCommon.New, "NtFile")]
[OutputType(typeof(NtFile))]
public class NewNtFileCmdlet : GetNtFileCmdlet
{
    /// <summary>
    /// <para type="description">Specify the file attributes for the new file.</para>
    /// </summary>
    [Parameter]
    [Alias("Attributes")]
    public FileAttributes FileAttribute { get; set; }

    /// <summary>
    /// <para type="description">Specify the disposition for creating the file.</para>
    /// </summary>
    [Parameter]
    public FileDisposition Disposition { get; set; }

    /// <summary>
    /// <para type="description">Specify an EA buffer to pass to the create file call.</para>
    /// </summary>
    [Parameter]
    public EaBuffer EaBuffer { get; set; }

    /// <summary>
    /// <para type="description">Specify to create a directory instead of a file.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter Directory { get; set; }

    /// <summary>
    /// <para type="description">Specify initial allocation size.</para>
    /// </summary>
    [Parameter]
    public long? AllocationSize { get; set; }

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
            if (Directory)
                opts |= FileOpenOptions.DirectoryFile;
            return NtFile.Create(obj_attributes, Access, FileAttribute,
                ShareMode, opts, Disposition, EaBuffer, AllocationSize);
        }
    }

    /// <summary>
    /// Constructor
    /// </summary>
    public NewNtFileCmdlet()
    {
        Disposition = FileDisposition.Create;
        FileAttribute = FileAttributes.Normal;
    }
}
