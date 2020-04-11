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
using NtApiDotNet.Win32.Device;
using System;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object
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
        public override string Path { get; set; }

        /// <summary>
        /// <para type="description">Specify that the path is a device GUID not a full path.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter DeviceGuid { get; set; }

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

        private static string ResolveRelativePath(SessionState state, string path, RtlPathType path_type)
        {
            var current_path = state.Path.CurrentFileSystemLocation;
            if (!current_path.Provider.Name.Equals("FileSystem", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("Can't make a relative Win32 path when not in a file system drive.");
            }

            switch (path_type)
            {
                case RtlPathType.Relative:
                    return System.IO.Path.Combine(current_path.Path, path);
                case RtlPathType.Rooted:
                    return $"{current_path.Drive.Name}:{path}";
                case RtlPathType.DriveRelative:
                    if (path.Substring(0, 1).Equals(current_path.Drive.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        return System.IO.Path.Combine(current_path.Path, path.Substring(2));
                    }
                    break;
            }

            return path;
        }

        /// <summary>
        /// Resolve a Win32 path using current PS session state.
        /// </summary>
        /// <param name="state">The session state.</param>
        /// <param name="path">The path to resolve.</param>
        /// <returns>The resolved Win32 path.</returns>
        public static string ResolveWin32Path(SessionState state, string path)
        {
            var path_type = NtFileUtils.GetDosPathType(path);
            if (path_type == RtlPathType.Rooted && path.StartsWith(@"\??"))
            {
                path_type = RtlPathType.LocalDevice;
            }
            switch (path_type)
            {
                case RtlPathType.Relative:
                case RtlPathType.DriveRelative:
                case RtlPathType.Rooted:
                    path = ResolveRelativePath(state, path, path_type);
                    break;
            }

            return NtFileUtils.DosFileNameToNt(path);
        }
        
        internal static string ResolvePath(SessionState state, string path, bool win32_path)
        {
            if (win32_path)
            {
                return ResolveWin32Path(state, path);
            }
            else
            {
                return path;
            }
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

            return ResolvePath(SessionState, Path, Win32Path);
        }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            using (Transaction?.Enable())
            {
                return NtFile.Open(obj_attributes, Access, ShareMode, Options);
            }
        }
    }
}
