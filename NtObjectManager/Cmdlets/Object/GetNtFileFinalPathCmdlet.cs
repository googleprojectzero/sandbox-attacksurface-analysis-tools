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

using NtApiDotNet;
using NtApiDotNet.Win32;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object
{
    /// <summary>
    /// <para type="synopsis">Get the final path name for a file.</para>
    /// <para type="description">This cmdlet gets the final pathname for a file.</para>
    /// </summary>
    /// <example>
    ///   <code>Get-NtFileFinalPath -File $f</code>
    ///   <para>Get the path for the file.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtFileFinalPath -Path "\??\c:\windows\notepad.exe"</code>
    ///   <para>Get the path for the file by path.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtFileFinalPath -Path "c:\windows\notepad.exe" -Win32Path</code>
    ///   <para>Get the path for the file by win32 path.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtFileFinalPath -Path "\??\c:\windows\notepad.exe" -FormatWin32Path</code>
    ///   <para>Get the path as a win32 path.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtFileFinalPath -Path "\??\c:\windows\notepad.exe" -FormatWin32Path -Flags NameGuid</code>
    ///   <para>Get the path as a volume GUID win32 path.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "NtFileFinalPath", DefaultParameterSetName = "Default")]
    [OutputType(typeof(string))]
    public class GetNtFileFinalPathCmdlet : BaseNtFilePropertyCmdlet
    {
        /// <summary>
        /// <para type="description">Specify to format the links as Win32 paths.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter FormatWin32Path { get; set; }

        /// <summary>
        /// <para type="description">Specify the name format when formatting as a Win32 path.</para>
        /// </summary>
        [Parameter]
        public Win32PathNameFlags Flags { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public GetNtFileFinalPathCmdlet()
            : base(FileAccessRights.Synchronize, FileShareMode.None, FileOpenOptions.None)
        {
        }

        private protected override void HandleFile(NtFile file)
        {
            WriteObject(FormatWin32Path ? file.GetWin32PathName(Flags) : file.FullPath);
        }
    }
}
