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

using NtApiDotNet;
using System.Management.Automation;

namespace NtObjectManager
{
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
        new public string Path { get; set; }

        /// <summary>
        /// Determine if the cmdlet can create objects.
        /// </summary>
        /// <returns>True if objects can be created.</returns>
        protected override bool CanCreateDirectories()
        {
            return false;
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
        /// <para type="description">If specified the path is considered a Win32 style path and converted automatically before being used.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter Win32Path { get; set; }

        /// <summary>
        /// Virtual method to return the value of the Path variable.
        /// </summary>
        /// <returns>The object path.</returns>
        protected override string GetPath()
        {
            if (Win32Path)
            {
                return FileUtils.DosFileNameToNt(Path);
            }
            else
            {
                return Path;
            }
        }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtFile.Open(obj_attributes, Access, ShareMode, Options);
        }
    }

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
    ///   <code>$obj = New-NtFile \??\C:\Windows\Temp\abc.txt -Disposition CreateIf</code>
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
    public sealed class NewNtFileCmdlet : GetNtFileCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the file attributes for the new file.</para>
        /// </summary>
        [Parameter]
        public FileAttributes Attributes { get; set; }

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
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtFile.Create(obj_attributes, Access, Attributes, ShareMode, Options, Disposition, EaBuffer);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public NewNtFileCmdlet()
        {
            Disposition = FileDisposition.Create;
            Attributes = FileAttributes.Normal;
        }
    }
}
