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
                return NtFileUtils.DosFileNameToNt(Path);
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
}
