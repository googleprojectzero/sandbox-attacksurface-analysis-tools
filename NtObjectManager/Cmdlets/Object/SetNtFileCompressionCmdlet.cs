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
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object;

/// <summary>
/// <para type="synopsis">Set the compression format for a file.</para>
/// <para type="description">This cmdlet sets the compression format for a file.</para>
/// </summary>
/// <example>
///   <code>Set-NtFileCompression -File $f -Format Default</code>
///   <para>Set the compression format for the file.</para>
/// </example>
/// <example>
///   <code>Set-NtFileCompression -Path "\??\c:\windows\notepad.exe" -Format Default</code>
///   <para>Set the compression format for the file by path</para>
/// </example>
/// <example>
///   <code>Set-NtFileCompression -Path "c:\windows\notepad.exe" -Win32Path -Format Default</code>
///   <para>Set the compression format for the file by win32 path</para>
/// </example>
[Cmdlet(VerbsCommon.Set, "NtFileCompression", DefaultParameterSetName = "Default")]
[OutputType(typeof(CompressionFormat))]
public class SetNtFileCompressionCmdlet : BaseNtFilePropertyCmdlet
{
    /// <summary>
    /// <para type="description">Specify to pass through the result.</para>
    /// </summary>
    [Parameter]
    public SwitchParameter PassThru { get; set; }

    /// <summary>
    /// <para type="description">Specify compression format to set.</para>
    /// </summary>
    [Parameter(Mandatory = true, Position = 1)]
    public CompressionFormat Format { get; set; }

    /// <summary>
    /// Constructor.
    /// </summary>
    public SetNtFileCompressionCmdlet()
        : base(FileAccessRights.ReadData | FileAccessRights.WriteData, 
              FileShareMode.None, FileOpenOptions.None)
    {
    }

    private protected override void HandleFile(NtFile file)
    {
        file.CompressionFormat = Format;
        if (PassThru)
        {
            WriteObject(file.CompressionFormat);
        }
    }
}
