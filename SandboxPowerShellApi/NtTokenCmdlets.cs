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
    public abstract class GetNtTokenCmdlet : Cmdlet
    {
        [Parameter]
        public TokenAccessRights Access { get; set; }

        [Parameter]
        public bool Duplicate { get; set; }

        [Parameter]
        public TokenType TokenType { get; set; }

        [Parameter]
        public SecurityImpersonationLevel ImpersonationLevel { get; set; }

        public GetNtTokenCmdlet()
        {
            Access = TokenAccessRights.MaximumAllowed;
            TokenType = TokenType.Impersonation;
            ImpersonationLevel = SecurityImpersonationLevel.Impersonation;
        }

        protected abstract NtToken GetToken(TokenAccessRights desired_access);

        protected override void ProcessRecord()
        {
            NtToken token = null;
            if (Duplicate)
            {
                using (NtToken base_token = GetToken(TokenAccessRights.Duplicate))
                {
                    token = base_token.DuplicateToken(TokenType, ImpersonationLevel, Access);
                }
            }
            else
            {
                token = GetToken(Access);
            }
            WriteObject(token);
        }
    }

    [Cmdlet(VerbsCommon.Get, "NtTokenPrimary")]
    public sealed class GetNtTokenPrimaryCmdlet : GetNtTokenCmdlet
    {
        [Parameter]
        public NtProcess Process { get; set; }

        [Parameter]
        public int ProcessId { get; set; }

        public GetNtTokenPrimaryCmdlet()
        {
            ProcessId = -1;
        }

        protected override NtToken GetToken(TokenAccessRights desired_access)
        {
            NtProcess process = Process ?? NtProcess.Current;
            if (ProcessId != -1)
            {
                return NtToken.OpenProcessToken(ProcessId, Duplicate, desired_access);
            }
            else
            {
                return NtToken.OpenProcessToken(process, Duplicate, desired_access);
            }
        }
    }

    [Cmdlet(VerbsCommon.Get, "NtTokenThread")]
    public class GetNtTokenThreadCmdlet : GetNtTokenCmdlet
    {
        [Parameter]
        public NtThread Thread { get; set; }

        [Parameter]
        public int ThreadId { get; set; }

        [Parameter]
        public bool OpenAsSelf { get; set; }

        public GetNtTokenThreadCmdlet()
        {
            ThreadId = -1;
        }

        protected override NtToken GetToken(TokenAccessRights desired_access)
        {
            NtThread thread = Thread ?? NtThread.Current;
            if (ThreadId != -1)
            {
                return NtToken.OpenThreadToken(ThreadId, OpenAsSelf, false, desired_access);
            }
            else
            {
                return NtToken.OpenThreadToken(thread, OpenAsSelf, false, desired_access);
            }
        }
    }

    [Cmdlet(VerbsCommon.Get, "NtTokenEffective")]
    public sealed class GetNtTokenEffectiveCmdlet : GetNtTokenThreadCmdlet
    {
        protected override NtToken GetToken(TokenAccessRights desired_access)
        {
            NtToken token = base.GetToken(desired_access);
            if (token == null)
            {
                using (NtThread thread =
                    ThreadId == -1 ? (Thread ?? NtThread.Current).Duplicate(ThreadAccessRights.QueryInformation)
                    : NtThread.Open(ThreadId, ThreadAccessRights.QueryLimitedInformation))
                {
                    token = NtToken.OpenProcessToken(thread.GetProcessId(), false, desired_access);
                }
            }
            return token;
        }
    }
}
