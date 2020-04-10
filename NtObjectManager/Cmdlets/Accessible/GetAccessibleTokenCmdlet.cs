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
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Accessible
{
    /// <summary>
    /// <para type="description">Access check result for a token.</para>
    /// </summary>
    public class TokenAccessCheckResult : CommonAccessCheckResult
    {
        /// <summary>
        /// Process image path.
        /// </summary>
        public string ProcessName => ProcessTokenInfo.ProcessName;

        /// <summary>
        /// Process image path.
        /// </summary>
        public string ProcessImagePath => ProcessTokenInfo.ProcessImagePath;

        /// <summary>
        /// Process ID of the process.
        /// </summary>
        public int ProcessId => ProcessTokenInfo.ProcessId;

        /// <summary>
        /// Command line of the process.
        /// </summary>
        public string ProcessCommandLine => ProcessTokenInfo.ProcessCommandLine;

        /// <summary>
        /// Gets the information for the process token, not the token used to check access.
        /// </summary>
        public ProcessTokenInformation ProcessTokenInfo { get; }

        /// <summary>
        /// Token username
        /// </summary>
        public Sid UserName => ProcessTokenInfo.User;

        /// <summary>
        /// Token integrity level
        /// </summary>
        public TokenIntegrityLevel IntegrityLevel => ProcessTokenInfo.IntegrityLevel;

        /// <summary>
        /// Elevated token
        /// </summary>
        public bool Elevated => ProcessTokenInfo.Elevated;

        /// <summary>
        /// Restricted token
        /// </summary>
        public bool Restricted => ProcessTokenInfo.Restricted;

        /// <summary>
        /// Write restricted token
        /// </summary>
        public bool WriteRestricted => ProcessTokenInfo.WriteRestricted;

        /// <summary>
        /// App container token
        /// </summary>
        public bool AppContainer =>  ProcessTokenInfo.AppContainer;

        /// <summary>
        /// Is the token sandboxed.
        /// </summary>
        public bool Sandbox => ProcessTokenInfo.Sandbox;

        /// <summary>
        /// Get whether the token can be used for child processes.
        /// </summary>
        public bool NoChildProcess => ProcessTokenInfo.NoChildProcess;

        /// <summary>
        /// The session ID of the token.
        /// </summary>
        public int SessionId => ProcessTokenInfo.SessionId;

        /// <summary>
        /// Get the authentication ID.
        /// </summary>
        public Luid AuthenticationId => ProcessTokenInfo.AuthenticationId;

        internal TokenAccessCheckResult(NtToken token, NtProcess process, AccessMask granted_access, SecurityDescriptor sd, 
            TokenInformation token_info) 
            : base($"{process.Name}:{process.ProcessId}", token.NtType.Name, granted_access, token.NtType.GenericMapping, sd,
                token.NtType.AccessRightsType, false, token_info)
        {
            ProcessTokenInfo = new ProcessTokenInformation(token, process);
        }
    }

    /// <summary>
    /// <para type="synopsis">Get a list of tokens that can be opened by a specified token.</para>
    /// <para type="description">This cmdlet checks all processes for primary tokens tries to determine
    /// if one or more specified tokens can open them. If no tokens are specified then the 
    /// current process token is used.</para>
    /// </summary>
    /// <remarks>For best results this command should be run as an administrator with SeDebugPrivilege, ideally as SYSTEM.</remarks>
    /// <example>
    ///   <code>Get-AccessibleToken</code>
    ///   <para>Check all accessible tokens for the current process token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-AccessibleToken -ProcessIds 1234,5678</code>
    ///   <para>>Check all accessible tokens for the process tokens of PIDs 1234 and 5678</para>
    /// </example>
    /// <example>
    ///   <code>$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low&#x0A;Get-AccessibleToken -Tokens $token -AccessRights GenericWrite</code>
    ///   <para>Get all tokens with can be written by a low integrity copy of current token.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "AccessibleToken")]
    [OutputType(typeof(TokenAccessCheckResult))]
    public class GetAccessibleTokenCmdlet : CommonAccessBaseWithAccessCmdlet<TokenAccessRights>
    {
        /// <summary>
        /// <para type="description">Specify that dead process tokens should be shown.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter ShowDeadProcesses { get; set; }

        /// <summary>
        /// <para type="description">Specify to only look for processes in the current session.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter CurrentSession { get; set; }

        private bool CheckSession(NtProcess p, int check_session_id)
        {
            var session_id = p.GetSessionId(false);
            return session_id.IsSuccess && session_id.Result == check_session_id;
        }

        private protected override void RunAccessCheck(IEnumerable<TokenEntry> tokens)
        {
            if (!NtToken.EnableDebugPrivilege())
            {
                WriteWarning("Current process doesn't have SeDebugPrivilege, results may be inaccurate");
            }

            NtType type = NtType.GetTypeByType<NtToken>();
            AccessMask access_rights = type.MapGenericRights(Access);
            int current_session_id = NtProcess.Current.SessionId;

            using (var procs = NtProcess.GetProcesses(ProcessAccessRights.QueryInformation | ProcessAccessRights.ReadControl, false).ToDisposableList())
            {
                IEnumerable<NtProcess> proc_enum = procs;
                if (CurrentSession)
                {
                    proc_enum = proc_enum.Where(p => CheckSession(p, current_session_id));
                }
                foreach (var proc in proc_enum.Where(p => ShowDeadProcesses || !p.IsDeleting))
                {
                    using (var result = NtToken.OpenProcessToken(proc, TokenAccessRights.ReadControl | TokenAccessRights.Query, false))
                    {
                        if (!result.IsSuccess)
                        {
                            WriteWarning($"Couldn't open token for Process {proc.Name} PID: {proc.ProcessId} Status: {result.Status}");
                            continue;
                        }

                        NtToken primary_token = result.Result;
                        var sd_result = primary_token.GetSecurityDescriptor(SecurityInformation.AllBasic, false);
                        if (!sd_result.IsSuccess)
                        {
                            WriteWarning($"Couldn't get token's Security Descriptor for Process {proc.Name} PID: {proc.ProcessId} Status: {sd_result.Status}");
                            continue;
                        }

                        var sd = sd_result.Result;
                        string process_name = proc.Name;
                        string process_cmdline = proc.CommandLine;
                        string image_path = proc.FullPath;
                        int process_id = proc.ProcessId;

                        foreach (var token in tokens)
                        {
                            if (proc.GetMaximumAccess(token.Token).HasFlag(ProcessAccessRights.QueryLimitedInformation))
                            {
                                AccessMask granted_access = NtSecurity.GetMaximumAccess(sd, token.Token, type.GenericMapping);
                                if (IsAccessGranted(granted_access, access_rights))
                                {
                                    WriteObject(new TokenAccessCheckResult(primary_token, proc,
                                        granted_access, sd, token.Information));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
