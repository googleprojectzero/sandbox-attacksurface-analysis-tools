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
    /// <para type="synopsis">Open an NT token from different sources.</para>
    /// <para type="description">This cmdlet gets a token from from on of multiple possible sources. You can specify either a Primary process token, a Thread impersonation token, an Effective token, a Clipboard token or a Logon token.</para>
    /// <para>Note that tokens objects need to be disposed of after use, therefore capture them in Use-NtObject or manually Close them once used.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = Get-NtToken -Primary</code>
    ///   <para>Get current process' primary token.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtToken -Primary -Access Duplicate</code>
    ///   <para>Get current process' primary token for Duplicate access.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtToken -Primary -Duplicate -TokenType Impersonation -ImpersonationLevel Impersonation</code>
    ///   <para>Get current process' primary token and convert to an impersonation token.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtTokenPrimary -Access AdjustPrivileges&#x0A;$obj.SetPrivilege("SeDebugPrivilege", $true)</code>
    ///   <para>Enable debug privilege on current token.</para>
    /// </example>
    /// <example>
    ///   <code>$process = Get-NtProcess -ProcessId 1234&#x0A;$obj = Get-NtToken -Primary -Process $process</code>
    ///   <para>Get process token for a specific process.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtToken -Primary -ProcessId 1234</code>
    ///   <para>Get process token for a specific process by process ID.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtToken -Primary&#x0A;$obj.GetPrivileges()</code>
    ///   <para>Query the privileges of a token.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtToken -Primary&#x0A;$obj.GetGroups()</code>
    ///   <para>Query the groups of a token.</para>
    /// </example>
    /// <example>
    ///   <code>$thread = Get-NtThread -ThreadId 1234&#x0A;$obj = Get-NtToken -Impersonation -Thread $thread</code>
    ///   <para>Get the impersonation token for a specific thread.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtToken -Impersonation -ThreadId 1234</code>
    ///   <para>Get impersonation token for a specific thread by ID.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtToken -Effective -ThreadId 1234</code>
    ///   <para>Get the effective token for a specific thread by ID.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtToken -Clipboard</code>
    ///   <para>Get the current clipboard token.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Get, "NtToken")]
    public sealed class GetNtTokenCmdlet : Cmdlet
    {
        /// <summary>
        /// <para type="description">Specify access rights for the token.</para>
        /// </summary>
        [Parameter]
        public TokenAccessRights Access { get; set; }

        /// <summary>
        /// <para type="description">Return a duplicated version of the token. The type of token is specified using -TokenType and -ImpersonationLevel</para>
        /// </summary>
        [Parameter]
        public SwitchParameter Duplicate { get; set; }

        /// <summary>
        /// <para type="description">Specify the type of token to create if -Duplicate is specified.</para>
        /// </summary>
        [Parameter]
        public TokenType TokenType { get; set; }

        /// <summary>
        /// <para type="description">Specify the impersonation level of the token to create if -Duplicate is specified and TokenType is Impersonation.</para>
        /// </summary>
        [Parameter]
        public SecurityImpersonationLevel ImpersonationLevel { get; set; }

        /// <summary>
        /// <para type="description">Get the primary token for a process.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "Primary")]
        public SwitchParameter Primary { get; set; }

        /// <summary>
        /// <para type="description">Specify the process to open the token from. If not set will use the current process.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Primary")]
        public NtProcess Process { get; set; }

        /// <summary>
        /// <para type="description">Specify the process to open the token from as a PID. Overridden by the Process parameter.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Primary"), Alias("pid")]
        public int? ProcessId { get; set; }

        /// <summary>
        /// <para type="description">Get an impersonation token for a thread.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "Impersonation")]
        public SwitchParameter Impersonation { get; set; }

        /// <summary>
        /// <para type="description">If thread impersonation token doesn't exist then get the primary token for the associated process. This is getting the "effective" token for the thread.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "Effective")]
        public SwitchParameter Effective { get; set; }

        /// <summary>
        /// <para type="description">Specify the thread to open the token from. If not set will use the current thread.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Impersonation"), Parameter(ParameterSetName = "Effective")]
        public NtThread Thread { get; set; }

        /// <summary>
        /// <para type="description">Specify the thread to open the token from by ID.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Impersonation"), Parameter(ParameterSetName = "Effective"), Alias("tid")]
        public int? ThreadId { get; set; }

        /// <summary>
        /// <para type="description">Specify the token should be open with the process identity rather than the impersonated identity.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Impersonation"), Parameter(ParameterSetName = "Effective")]
        public bool OpenAsSelf { get; set; }

        /// <summary>
        /// <para type="description">Get the current clipboard token.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "Clipboard")]
        public SwitchParameter Clipboard { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public GetNtTokenCmdlet()
        {
            Access = TokenAccessRights.MaximumAllowed;
            TokenType = TokenType.Impersonation;
            ImpersonationLevel = SecurityImpersonationLevel.Impersonation;
        }

        private NtToken GetPrimaryToken(TokenAccessRights desired_access)
        {
            if (ProcessId.HasValue)
            {
                return NtToken.OpenProcessToken(ProcessId.Value, false, desired_access);
            }

            return NtToken.OpenProcessToken(Process ?? NtProcess.Current, false, desired_access);
        }

        private NtToken GetClipboardToken(TokenAccessRights desired_access)
        {
            return HandleUtils.TokenUtils.GetTokenFromClipboard(desired_access);
        }

        private NtToken GetImpersonationToken(TokenAccessRights desired_access)
        {
            if (ThreadId.HasValue)
            {
                return NtToken.OpenThreadToken(ThreadId.Value, OpenAsSelf, false, desired_access);
            }

            return NtToken.OpenThreadToken(Thread ?? NtThread.Current, OpenAsSelf, false, desired_access);
        }

        private NtToken GetEffectiveToken(TokenAccessRights desired_access)
        {
            NtToken token = GetImpersonationToken(desired_access);
            if (token != null)
            {
                return token;
            }

            if (Thread == null && !ThreadId.HasValue)
            {
                return NtToken.OpenProcessToken(NtProcess.Current, false, desired_access);
            }

            int pid;
            if (Thread != null)
            {
                pid = Thread.ProcessId;
            }
            else
            {
                using (NtThread thread = NtThread.Open(ThreadId.Value, ThreadAccessRights.QueryLimitedInformation))
                {
                    pid = thread.ProcessId;
                }
            }

            return NtToken.OpenProcessToken(pid, false, desired_access);
        }

        private NtToken GetToken(TokenAccessRights desired_access)
        {
            if (Primary)
            {
                return GetPrimaryToken(desired_access);
            }
            else if (Impersonation)
            {
                return GetImpersonationToken(desired_access);
            }
            else if (Effective)
            {
                return GetEffectiveToken(desired_access);
            }
            else if (Clipboard)
            {
                return GetClipboardToken(desired_access);
            }
            
            throw new ArgumentException("Unknown token type");
        }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
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
}
