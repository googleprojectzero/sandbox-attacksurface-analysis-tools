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
using System;
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
        public override string Path { get; set; }

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
        /// <para type="description">Specify to create a directory instead of a file.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter Directory { get; set; }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            using (Transaction?.Enable())
            {
                return NtFile.Create(obj_attributes, Access, Attributes,
                    ShareMode, Options | (Directory ? FileOpenOptions.DirectoryFile : FileOpenOptions.None), Disposition, EaBuffer);
            }
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

    /// <summary>
    /// <para type="synopsis">Open a existing NT file object.</para>
    /// <para type="description">This cmdlet opens a existing NT file object. The absolute path to the object in the NT object manager name space can be specified. 
    /// It's also possible to open the object relative to an existing object by specified the -Root parameter. To simply calling it's also possible to specify the
    /// path in a Win32 format when using the -Win32Path parameter.</para>
    /// </summary>
    /// <example>
    ///   <code>Remove-NtFile \??\C:\path\file.exe</code>
    ///   <para>Delete a file object with an absolute path.</para>
    /// </example>
    /// <example>
    ///   <code>$root = Get-NtFile \??\C:\path&#x0A;Remove-NtFile file.exe -Root $root</code>
    ///   <para>Delete a file object with a relative path.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtFile c:\path\file.exe -Win32Path</code>
    ///   <para>Delete a file object with an absolute win32 path.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtFile ..\..\..\path\file.exe -Win32Path</code>
    ///   <para>Delete a file object with a relative win32 path.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtFile \??\C:\path\file.exe -PosixSemantics</code>
    ///   <para>Delete a file object with POSIX semantics (needs Win10 RS3+).</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtFile \??\C:\path\file.exe -DeleteReparsePoint</code>
    ///   <para>Delete a file reparse point rather than following the link.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtFile \??\C:\path\file.exe -ShareMode Read</code>
    ///   <para>Delete a file object specifying a Read sharemode.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Remove, "NtFile")]
    public class RemoveNtFileCmdlet : GetNtFileCmdlet
    {
        /// <summary>
        /// <para type="description">Specify whether to delete with POSIX semantics.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter PosixSemantics;

        /// <summary>
        /// <para type="description">Specify whether to delete the reparse point or the target.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter DeleteReparsePoint;

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            using (var file = NtFile.Open(obj_attributes, FileAccessRights.Delete | Access, ShareMode,
                Options | (DeleteReparsePoint ? FileOpenOptions.OpenReparsePoint : FileOpenOptions.None)))
            {
                if (PosixSemantics)
                {
                    file.DeleteEx(FileDispositionInformationExFlags.PosixSemantics | FileDispositionInformationExFlags.Delete);
                }
                else
                {
                    file.Delete();
                }
            }
            return null;
        }
    }

    /// <summary>
    /// <para type="synopsis">Opens an existing NT named pipe file object.</para>
    /// <para type="description">This cmdlet opens an existing NT named pipe file object. The absolute path to the object in the NT object manager name space can be specified. 
    /// It's also possible to open the object relative to an existing object by specified the -Root parameter. This only works if the caller has permission to access the
    /// pipe server object and the maximum number of instances is not exceeded.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = Get-NtNamedPipeFile \??\pipe\abc</code>
    ///   <para>Opens an existing file named pipe object with an absolute path.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtNamedPipeFile \\.\pipe\abc -Win32Path</code>
    ///   <para>Opens an existing file named pipe object with an absolute win32 path.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtNamedPipeFile \??\pipe\abc -Disposition OpenIf</code>
    ///   <para>Opens an existing file named pipe object with an absolute path. If the file already exists then open it rather than failing.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Get, "NtNamedPipeFile")]
    [OutputType(typeof(NtFile))]
    public class GetNtNamedPipeFileCmdlet : GetNtFileCmdlet
    {
        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtFile.CreateNamedPipe(obj_attributes, Access, ShareMode, Options, FileDisposition.Open, NamedPipeType.Bytestream,
                NamedPipeReadMode.ByteStream, NamedPipeCompletionMode.CompleteOperation, 0, 0, 0, NtWaitTimeout.FromMilliseconds(0));
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public GetNtNamedPipeFileCmdlet()
        {
            ShareMode = FileShareMode.Read | FileShareMode.Write;
            Options = FileOpenOptions.SynchronousIoNonAlert;
            Access = FileAccessRights.GenericRead | FileAccessRights.GenericWrite | FileAccessRights.Synchronize;
        }
    }

    /// <summary>
    /// <para type="synopsis">Create a new NT named pipe file object.</para>
    /// <para type="description">This cmdlet creates a new NT named pipe file object. The absolute path to the object in the NT object manager name space can be specified. 
    /// It's also possible to open the object relative to an existing object by specified the -Root parameter.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = New-NtNamedPipeFile \??\pipe\abc</code>
    ///   <para>Creates a new file named pipe object with an absolute path.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = New-NtNamedPipeFile \??\pipe\abc -MaximumInstances 100</code>
    ///   <para>Creates a new file named pipe object with an absolute path and with a maximum of 100 instances.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = New-NtNamedPipeFile \??\pipe\abc -UnlimitedInstances</code>
    ///   <para>Creates a new file named pipe object with an absolute path and with a unlimited maximum number of instances.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = New-NtNamedPipeFile \\.\pipe\abc -Win32Path</code>
    ///   <para>Creates a new file named pipe object with an absolute win32 path.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = New-NtNamedPipeFile \??\pipe\abc -Disposition OpenIf</code>
    ///   <para>Creates a new file named pipe object with an absolute path. If the file already exists then open it rather than failing.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.New, "NtNamedPipeFile")]
    [OutputType(typeof(NtFile))]
    public class NewNtNamedPipeFileCmdlet : GetNtFileCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the disposition for creating the file.</para>
        /// </summary>
        [Parameter]
        public FileDisposition Disposition { get; set; }

        /// <summary>
        /// <para type="description">Specify the default timeout for the pipe in MS</para>
        /// </summary>
        [Parameter]
        public int DefaultTimeoutMs { get; set; }

        /// <summary>
        /// <para type="description">Specify the pipe type.</para>
        /// </summary>
        [Parameter]
        public NamedPipeType PipeType { get; set; }

        /// <summary>
        /// <para type="description">Specify the pipe read mode.</para>
        /// </summary>
        [Parameter]
        public NamedPipeReadMode ReadMode { get; set; }

        /// <summary>
        /// <para type="description">Specify the pipe completion mode.</para>
        /// </summary>
        [Parameter]
        public NamedPipeCompletionMode CompletionMode { get; set; }

        /// <summary>
        /// <para type="description">Specify the maximum number of pipe instances (-1 is infinite).</para>
        /// </summary>
        [Parameter]
        public int MaximumInstances { get; set; }

        /// <summary>
        /// <para type="description">If specified an unlimited number of instances of this pipe can be created.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter UnlimitedInstances { get; set; }

        /// <summary>
        /// <para type="description">Specify the pipe input quota (0 is default).</para>
        /// </summary>
        [Parameter]
        public int InputQuota { get; set; }

        /// <summary>
        /// <para type="description">Specify the pipe output quota (0 is default).</para>
        /// </summary>
        [Parameter]
        public int OutputQuota { get; set; }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtFile.CreateNamedPipe(obj_attributes, Access, ShareMode, Options, Disposition, PipeType, 
                ReadMode, CompletionMode, UnlimitedInstances ? -1 : MaximumInstances, InputQuota, OutputQuota, NtWaitTimeout.FromMilliseconds(DefaultTimeoutMs));
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public NewNtNamedPipeFileCmdlet()
        {
            Disposition = FileDisposition.OpenIf;
            ReadMode = NamedPipeReadMode.ByteStream;
            CompletionMode = NamedPipeCompletionMode.QueueOperation;
            PipeType = NamedPipeType.Bytestream;
            MaximumInstances = 1;
            DefaultTimeoutMs = 50;
            ShareMode = FileShareMode.Read | FileShareMode.Write;
            Options = FileOpenOptions.SynchronousIoNonAlert;
            Access = FileAccessRights.GenericRead | FileAccessRights.GenericWrite | FileAccessRights.Synchronize;
        }
    }

    /// <summary>
    /// <para type="synopsis">Create a new NT mailslot file object.</para>
    /// <para type="description">This cmdlet creates a new NT mailslot file object. The absolute path to the object in the NT object manager name space can be specified. 
    /// It's also possible to open the object relative to an existing object by specified the -Root parameter.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = New-NtMailslotFile \??\mailslot\abc</code>
    ///   <para>Creates a new file mailslot object with an absolute path.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = New-NtMailslotFile \\.\mailslot\abc -Win32Path</code>
    ///   <para>Creates a new file mailslot object with an absolute win32 path.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.New, "NtMailslotFile")]
    [OutputType(typeof(NtFile))]
    public class NewNtMailslotFileCmdlet : GetNtFileCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the default timeout for the mailslot in MS (-1 for no timeout)</para>
        /// </summary>
        [Parameter]
        public int DefaultTimeoutMs { get; set; }
        
        /// <summary>
        /// <para type="description">Specify the maximum message size (0 means any size)</para>
        /// </summary>
        [Parameter]
        public int MaximumMessageSize { get; set; }

        /// <summary>
        /// <para type="description">Specify the mailslot quota.</para>
        /// </summary>
        [Parameter]
        public int MailslotQuota { get; set; }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtFile.CreateMailslot(obj_attributes, Access, Options, 
                MaximumMessageSize, MailslotQuota, DefaultTimeoutMs);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public NewNtMailslotFileCmdlet()
        {
            DefaultTimeoutMs = -1;
            Access = FileAccessRights.GenericRead | FileAccessRights.ReadAttributes | FileAccessRights.WriteDac;
        }
    }

    /// <summary>
    /// <para type="synopsis">Open and reads the reparse point buffer for file.</para>
    /// <para type="description">This cmdlet opens a existing NT file object and reads out the reparse point buffer data. 
    /// The absolute path to the object in the NT object manager name space can be specified. 
    /// It's also possible to open the object relative to an existing object by specified the -Root parameter.
    /// To simplify calling it's also possible to specify the path in a Win32 format when using the -Win32Path parameter.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = Get-NtFileReparsePoint \??\C:\XYZ</code>
    ///   <para>Reads the reparse point with an absolute path.</para>
    /// </example>
    /// <example>
    ///   <code>$root = Get-NtFile \??\C:\&#x0A;$obj = Get-NtFileReparsePoint XYZ -Root $root</code>
    ///   <para>Reads the reparse point with a relative path.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtFileReparsePoint C:\XYZ -Win32Path</code>
    ///   <para>Reads the reparse point with an absolute win32 path.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtFileReparsePoint ..\..\..\XYZ -Win32Path</code>
    ///   <para>Reads the reparse point with a relative win32 path.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "NtFileReparsePoint")]
    [OutputType(typeof(ReparseBuffer))]
    public class GetNtFileReparsePointCmdlet : GetNtFileCmdlet
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        public GetNtFileReparsePointCmdlet()
        {
            Options = FileOpenOptions.OpenReparsePoint;
        }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            Options |= FileOpenOptions.OpenReparsePoint;

            using (NtFile file = (NtFile)base.CreateObject(obj_attributes))
            {
                return file.GetReparsePoint();
            }
        }
    }

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
        /// <para type="description">Specify creating a mount point.</para>
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
        /// <para type="description">Specify the a raw reparse point buffer.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "ReparseBuffer", Position = 1)]
        public ReparseBuffer ReparseBuffer { get; set; }

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
                string target_path = Relative ? TargetPath : ResolvePath(SessionState, TargetPath, Win32Path);
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
                }
            }

            using (NtFile file = (NtFile)base.CreateObject(obj_attributes))
            {
                file.SetReparsePoint(ReparseBuffer);
            }

            return null;
        }
    }

    /// <summary>
    /// <para type="synopsis">Removes the reparse point buffer for file.</para>
    /// <para type="description">This cmdlet removes the reparse point buffer from an existing NT file object. 
    /// The absolute path to the object in the NT object manager name space can be specified. 
    /// It's also possible to open the object relative to an existing object by specified the -Root parameter.
    /// To simplify calling it's also possible to specify the path in a Win32 format when using the -Win32Path parameter.
    /// It will return the original reparse buffer that was removed.</para>
    /// </summary>
    /// <example>
    ///   <code>Remove-NtFileReparsePoint \??\C:\XYZ</code>
    ///   <para>Remove the reparse point with an absolute path.</para>
    /// </example>
    /// <example>
    ///   <code>$root = Get-NtFile \??\C:\&#x0A;Remove-NtFileReparsePoint XYZ -Root $root</code>
    ///   <para>Remove the reparse point with a relative path.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtFileReparsePoint C:\XYZ -Win32Path</code>
    ///   <para>Remove the reparse point with an absolute win32 path.</para>
    /// </example>
    /// <example>
    ///   <code>Remove-NtFileReparsePoint ..\..\..\XYZ -Win32Path</code>
    ///   <para>Remove the reparse point with a relative win32 path.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Remove, "NtFileReparsePoint")]
    [OutputType(typeof(ReparseBuffer))]
    public class RemoveNtFileReparsePointCmdlet : GetNtFileCmdlet
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        public RemoveNtFileReparsePointCmdlet()
        {
            Options = FileOpenOptions.OpenReparsePoint;
        }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            Options |= FileOpenOptions.OpenReparsePoint;

            using (NtFile file = (NtFile)base.CreateObject(obj_attributes))
            {
                return file.DeleteReparsePoint();
            }
        }
    }

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
                using (var token = NtToken.OpenEffectiveToken())
                {
                    if (!token.SetPrivilege(TokenPrivilegeValue.SeBackupPrivilege, PrivilegeAttributes.Enabled))
                    {
                        WriteWarning("OpenForBackup specified but caller doesn't have SeBackupPrivilege");
                    }
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
}
