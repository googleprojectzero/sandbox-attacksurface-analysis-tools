//  Copyright 2016 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http ://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using NtApiDotNet;
using System.Management.Automation;

namespace SandboxPowerShellApi
{
    [Cmdlet(VerbsCommon.Get, "NtFile")]
    public class GetNtFileCmdlet : NtObjectBaseCmdletWithAccess<FileAccessRights>
    {
        [Parameter(Position = 0, Mandatory = true)]
        new public string Path { get; set; }

        [Parameter]
        public FileShareMode ShareMode { get; set; }

        [Parameter]
        public FileOpenOptions Options { get; set; }

        [Parameter]
        public SwitchParameter Win32Path { get; set; }

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

        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtFile.Open(obj_attributes, Access, ShareMode, Options);
        }
    }

    [Cmdlet(VerbsCommon.New, "NtFile")]
    public sealed class NewNtFileCmdlet : GetNtFileCmdlet
    {
        [Parameter]
        public FileAttributes Attributes { get; set; }

        [Parameter]
        public FileDisposition Disposition { get; set; }

        [Parameter]
        public EaBuffer EaBuffer { get; set; }

        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtFile.Create(obj_attributes, Access, Attributes, ShareMode, Options, Disposition, EaBuffer);
        }
    }

    [Cmdlet(VerbsCommon.New, "NtFileEaBuffer")]
    public sealed class NewNtFileEaBuffer : Cmdlet
    {
        protected override void ProcessRecord()
        {
            WriteObject(new EaBuffer());
        }
    }
}
