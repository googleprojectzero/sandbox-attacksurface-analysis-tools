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
    [Cmdlet(VerbsCommon.Get, "NtProcess")]
    public class GetNtProcessCmdlet : Cmdlet
    {
        [Parameter]
        public int ProcessId { get; set; }

        [Parameter]
        public ProcessAccessRights Access { get; set; }

        public GetNtProcessCmdlet()
        {
            Access = ProcessAccessRights.MaximumAllowed;
            ProcessId = -1;
        }

        protected override void ProcessRecord()
        {
            NtProcess process = null;

            if (ProcessId == -1)
            {
                if ((Access & ProcessAccessRights.MaximumAllowed) == ProcessAccessRights.MaximumAllowed)
                {
                    process = NtProcess.Current.Duplicate();
                }
                else
                {
                    process = NtProcess.Current.Duplicate(Access);
                }
            }
            else
            {
                process = NtProcess.Open(ProcessId, Access);
            }

            WriteObject(process);
        }
    }
}
