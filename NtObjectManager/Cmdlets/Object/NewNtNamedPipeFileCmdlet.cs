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
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Create a new NT named pipe file object.</para>
/// <para type="description">This cmdlet creates a new NT named pipe file object. The absolute path to the object in the NT object manager name space can be specified. 
/// It's also possible to open the object relative to an existing object by specified the -Root parameter. The ShareMode is used to determine data direction, specify
/// Write to make an inbound pipe (client->server), Read to make an outbound pipe (server->client) and Read, Write to make full duplex.</para>
/// </summary>
/// <example>
///   <code>$obj = New-NtNamedPipeFile \??\pipe\abc</code>
///   <para>Creates a new, full duplex file named pipe object with an absolute path.</para>
/// </example>
/// <example>
///   <code>$obj = New-NtNamedPipeFile \??\pipe\abc -ShareMode Read</code>
///   <para>Creates a new outbound file named pipe object with an absolute path.</para>
/// </example>
/// /// <example>
///   <code>$obj = New-NtNamedPipeFile \??\pipe\abc -ShareMode Write</code>
///   <para>Creates a new inbound file named pipe object with an absolute path.</para>
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
