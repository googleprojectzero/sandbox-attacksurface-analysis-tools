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
