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
    [Cmdlet(VerbsCommon.Get, "NtThread")]
    public class GetNtThreadCmdlet : Cmdlet
    {
        [Parameter]        
        public int ThreadId { get; set; }

        [Parameter]
        public ThreadAccessRights Access { get; set; }

        public GetNtThreadCmdlet()
        {
            Access = ThreadAccessRights.MaximumAllowed;
            ThreadId = -1;
        }

        protected override void ProcessRecord()
        {
            NtThread thread = null;

            if (ThreadId == -1)
            {
                if ((Access & ThreadAccessRights.MaximumAllowed) == ThreadAccessRights.MaximumAllowed)
                {
                    thread = NtThread.Current.Duplicate();
                }
                else
                {
                    thread = NtThread.Current.Duplicate(Access);
                }
            }
            else
            {
                thread = NtThread.Open(ThreadId, Access);
            }

            WriteObject(thread);
        }
    }
}
