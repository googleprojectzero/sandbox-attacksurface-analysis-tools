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

using SandboxAnalysisUtils;
using NtApiDotNet;
using System;
using System.Management.Automation;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="synopsis">Open an NT token from different sources.</para>
    /// <para type="description">This cmdlet gets a token from one of multiple possible sources. You can specify either a Primary process token, a Thread impersonation token, an Effective token, a Clipboard token a Logon/S4U token or the anonymous token.</para>
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
    ///   <code>$obj = Get-NtToken -Primary -Duplicate -TokenType Primary -IntegrityLevel Low</code>
    ///   <para>Get current process token, duplicate as primary and set integrity level to Low.</para>
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
    /// <example>
    ///   <code>$obj = Get-NtToken -Logon -User Bob -Password BobP@ssword</code>
    ///   <para>Get network logon token for user Bob in the current domain with password BobP@ssword.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtToken -Logon -User Bob -Password BobP@ssword -Domain BADGERS -LogonType Interactive</code>
    ///   <para>Get interactive logon token for BADGERS\\Bob with password BobP@ssword.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtToken -S4U -User Bob -Domain BADGERS</code>
    ///   <para>Get S4U network logon token for BADGERS\\Bob with no password.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtToken -Anonymous</code>
    ///   <para>Get the anonymous logon token.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Get, "NtToken")]
    [OutputType(typeof(NtToken))]
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
        /// <para type="description">Specify the integrity level of the token to if -Duplicate is specified.</para>
        /// </summary>
        [Parameter]
        public TokenIntegrityLevel? IntegrityLevel { get; set; }

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
        public SwitchParameter OpenAsSelf { get; set; }

        /// <summary>
        /// <para type="description">Get the current clipboard token.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "Clipboard")]
        public SwitchParameter Clipboard { get; set; }

        /// <summary>
        /// <para type="description">Get a logon token.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "Logon")]
        public SwitchParameter Logon { get; set; }

        /// <summary>
        /// <para type="description">Get an Services for User (S4U) logon token.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "S4U")]
        public SwitchParameter S4U { get; set; }

        /// <summary>
        /// <para type="description">Specify username for logon token.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "Logon"), Parameter(Mandatory = true, ParameterSetName = "S4U")]
        public string User { get; set; }

        /// <summary>
        /// <para type="description">Specify password for logon token.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Logon")]
        public string Password { get; set; }

        /// <summary>
        /// <para type="description">Specify domain for logon token.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Logon"), Parameter(ParameterSetName = "S4U")]
        public string Domain { get; set; }

        /// <summary>
        /// <para type="description">Specify logon type for logon token.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Logon"), Parameter(ParameterSetName = "S4U")]
        public SecurityLogonType LogonType { get; set; }

        /// <summary>
        /// <para type="description">Get anonymous token.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "Anonymous")]
        public SwitchParameter Anonymous { get; set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        public GetNtTokenCmdlet()
        {
            Access = TokenAccessRights.MaximumAllowed;
            TokenType = TokenType.Impersonation;
            ImpersonationLevel = SecurityImpersonationLevel.Impersonation;
            Domain = Environment.UserDomainName;
            LogonType = SecurityLogonType.Network;
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
            return TokenUtils.GetTokenFromClipboard(desired_access);
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

        private NtToken GetLogonToken(TokenAccessRights desired_access)
        {
            using (NtToken token = TokenUtils.GetLogonUserToken(User, Domain, Password, LogonType))
            {
                if (desired_access == TokenAccessRights.MaximumAllowed)
                {
                    return token.Duplicate();
                }
                return token.Duplicate(desired_access);
            }
        }

        private NtToken GetS4UToken(TokenAccessRights desired_access)
        {
            using (NtToken token = SandboxAnalysisUtils.LogonUtils.LogonS4U(User, Domain, LogonType))
            {
                if (desired_access == TokenAccessRights.MaximumAllowed)
                {
                    return token.Duplicate();
                }
                return token.Duplicate(desired_access);
            }
        }

        private NtToken GetAnonymousToken(TokenAccessRights desired_access)
        {
            return TokenUtils.GetAnonymousToken(desired_access);
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
            else if (Logon)
            {
                return GetLogonToken(desired_access);
            }
            else if (S4U)
            {
                return GetS4UToken(desired_access);
            }
            else if (Anonymous)
            {
                return GetAnonymousToken(desired_access);
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
                    if (IntegrityLevel.HasValue)
                    {
                        using (NtToken set_token = token.Duplicate(TokenAccessRights.AdjustDefault))
                        {
                            set_token.SetIntegrityLevel(IntegrityLevel.Value);
                        }
                    }
                }
            }
            else
            {
                token = GetToken(Access);
            }
            WriteObject(token);
        }
    }

    /// <summary>
    /// <para type="synopsis">Filter an existing NT token.</para>
    /// <para type="description">This cmdlet takes a token and filters (also referred to as restricting) it.</para>
    /// <para>Note that tokens objects need to be disposed of after use, therefore capture them in Use-NtObject or manually Close them once used.</para>
    /// </summary>
    /// <example>
    ///   <code>$token = Use-NtObject($tmp = Get-NtToken -Primary) { Get-NtFilteredToken $tmp -Flags DisableMaxPrivileges }</code>
    ///   <para>Get current process' primary token and disable the maximum privileges.</para>
    /// </example>
    /// <example>
    ///   <code>$token = Use-NtObject($tmp = Get-NtToken -Primary) { Get-NtFilteredToken $tmp -SidsToDisable "Everyone","BA" }</code>
    ///   <para>Get current process' primary token and set Everyone and Built Administrators groups to deny only.</para>
    /// </example>
    /// <example>
    ///   <code>$token = Use-NtObject($tmp = Get-NtToken -Primary) { Get-NtFilteredToken $tmp -SidsToDisable "Everyone","BA" }</code>
    ///   <para>Get current process' primary token and set Everyone and Built Administrators groups to deny only.</para>
    /// </example>
    /// <example>
    ///   <code>$token = Use-NtObject($tmp = Get-NtToken -Primary) { Get-NtFilteredToken $tmp -RestrictedSids $tmp.Groups }</code>
    ///   <para>Get current process' primary token and add all groups as restricted SIDs.</para>
    /// </example>
    /// <example>
    ///   <code>$token = Use-NtObject($tmp = Get-NtToken -Primary) { Get-NtFilteredToken $tmp -Flags LuaToken }</code>
    ///   <para>Get current process' primary token and convert it to a LUA token.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Get, "NtFilteredToken")]
    [OutputType(typeof(NtToken))]
    public sealed class GetNtFilteredTokenCmdlet : Cmdlet
    {
        /// <summary>
        /// <para type="description">Specify access rights for the token.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0)]
        public NtToken Token { get; set; }

        /// <summary>
        /// <para type="description">Specify list of privileges to delete.</para>
        /// </summary>
        [Parameter]
        public TokenPrivilege[] PrivilegesToDelete { get; set; }

        /// <summary>
        /// <para type="description">Specify list group SIDS to disable.</para>
        /// </summary>
        [Parameter]
        public UserGroup[] SidsToDisable { get; set; }

        /// <summary>
        /// <para type="description">Specify list restricted SIDS to add to token.</para>
        /// </summary>
        [Parameter]
        public UserGroup[] RestrictedSids { get; set; }

        /// <summary>
        /// <para type="description">Specify filter flags.</para>
        /// </summary>
        [Parameter]
        public FilterTokenFlags Flags { get; set; }

        private static void AddLuids(HashSet<Luid> set, IEnumerable<Luid> luids)
        {
            foreach (Luid l in luids)
            {
                set.Add(l);
            }
        }

        private IEnumerable<Luid> GetPrivileges(IEnumerable<TokenPrivilege> privs)
        {
            if (privs == null)
            {
                return null;
            }
            return privs.Select(p => p.Luid);
        }

        private static IEnumerable<Sid> GroupsToSids(IEnumerable<UserGroup> groups)
        {
            if (groups == null)
            {
                return null;
            }
            return groups.Select(g => g.Sid);
        }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            WriteObject(Token.Filter(Flags, GroupsToSids(SidsToDisable), 
                GetPrivileges(PrivilegesToDelete), GroupsToSids(RestrictedSids)));
        }
    }

    /// <summary>
    /// <para type="synopsis">Get a LowBox version of an existing NT token.</para>
    /// <para type="description">This cmdlet takes a token and creates a new lowbox token from it.</para>
    /// <para>Note that tokens objects need to be disposed of after use, therefore capture them in Use-NtObject or manually Close them once used.</para>
    /// </summary>
    /// <example>
    ///   <code>$token = Use-NtObject($tmp = Get-NtToken -Primary) { Get-NtLowBoxToken $tmp -PackageSid "Application.Name" }</code>
    ///   <para>Get current process' primary token create a lowbox token with a named package.</para>
    /// </example>
    /// <example>
    ///   <code>$token = Use-NtObject($tmp = Get-NtToken -Primary) { Get-NtLowBoxToken $tmp -PackageSid "S-1-15-2-1-2-3-4-5-6-7" }</code>
    ///   <para>Get current process' primary token create a lowbox token with a package Sid.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Get, "NtLowBoxToken")]
    [OutputType(typeof(NtToken))]
    public sealed class GetNtLowBoxTokenCmdlet : Cmdlet
    {
        /// <summary>
        /// <para type="description">Specify access rights for the token.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 0)]
        public NtToken Token { get; set; }

        /// <summary>
        /// <para type="description">Specify package SID or a name.</para>
        /// </summary>
        [Parameter(Mandatory = true)]
        public string PackageSid { get; set; }

        /// <summary>
        /// <para type="description">Specify list of capability SIDS to add to token.</para>
        /// </summary>
        [Parameter]
        public Sid[] CapabilitySids { get; set; }

        /// <summary>
        /// <para type="description">Specify list of handles to capture with lowbox token..</para>
        /// </summary>
        [Parameter]
        public NtObject[] Handles { get; set; }
        
        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            Sid package_sid = SandboxAnalysisUtils.TokenUtils.GetPackageSidFromName(PackageSid);
            if (!NtSecurity.IsPackageSid(package_sid))
            {
                throw new ArgumentException(String.Format("Invalid Package Sid {0}", package_sid));
            }

            WriteObject(Token.CreateLowBoxToken(package_sid, CapabilitySids ?? new Sid[0], Handles ?? new NtObject[0], TokenAccessRights.MaximumAllowed));
        }
    }
}
