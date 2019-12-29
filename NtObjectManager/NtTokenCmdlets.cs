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
using System.Collections.Generic;
using System.Linq;
using NtApiDotNet.Win32;
using System.Security;
using System.Runtime.InteropServices;
using NtApiDotNet.Token;

namespace NtObjectManager
{
    /// <summary>
    /// <para type="description">Type of service account to create.</para>
    /// </summary>
    public enum ServiceAccountType
    {
        /// <summary>
        /// Create SYSTEM token.
        /// </summary>
        System,
        /// <summary>
        /// Create Local Service token.
        /// </summary>
        LocalService,
        /// <summary>
        /// Create Network Service token.
        /// </summary>
        NetworkService
    }

    /// <summary>
    /// <para type="synopsis">Open an NT token from different sources.</para>
    /// <para type="description">This cmdlet gets a token from one of multiple possible sources. You can specify either a Primary process token, a Thread impersonation token, an Effective token, 
    /// a Clipboard token, a Logon/S4U token, the anonymous token, a lowbox or a filtered token.</para>
    /// <para>Note that tokens objects need to be disposed of after use, therefore capture them in Use-NtObject or manually Close them once used.</para>
    /// </summary>
    /// <example>
    ///   <code>$obj = Get-NtToken</code>
    ///   <para>Get current process' primary token.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtToken -Pseudo</code>
    ///   <para>Get current process' pseudo primary token.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtToken -Primary</code>
    ///   <para>Get current process' primary token (-Primary is optional)</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtToken -Access Duplicate</code>
    ///   <para>Get current process' primary token for Duplicate access.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtToken -Duplicate -TokenType Impersonation -ImpersonationLevel Impersonation</code>
    ///   <para>Get current process' primary token and convert to an impersonation token.</para>
    /// </example>
    /// <example>
    ///   <code>$obj = Get-NtToken -Duplicate -TokenType Primary -IntegrityLevel Low</code>
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
    /// <example>
    ///   <code>Get-NtToken -Filtered -Flags DisableMaxPrivileges</code>
    ///   <para>Get current process' primary token and disable the maximum privileges.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtToken -Filtered -SidsToDisable "WD","BA"</code>
    ///   <para>Get current process' primary token and set Everyone and Built Administrators groups to deny only.</para>
    /// </example>
    /// <example>
    ///   <code>$token = Use-NtObject($tmp = Get-NtToken -Primary) { Get-NtToken -Filtered -Token $tmp -RestrictedSids $tmp.Groups }</code>
    ///   <para>Get current process' primary token, pass it as an explicit token and add all groups as restricted SIDs.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtToken -Filtered -Flags LuaToken</code>
    ///   <para>Get current process' primary token and convert it to a LUA token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtToken -LowBox -PackageSid "Application.Name"</code>
    ///   <para>Get current process' primary token create a lowbox token with a named package.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtToken -LowBox -PackageSid "S-1-15-2-1-2-3-4-5-6-7"</code>
    ///   <para>Get current process' primary token create a lowbox token with a package Sid.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtToken -LowBox -PackageSid "Application.Name" -CapabilitySid "readRegistry", "S-1-15-3-1"</code>
    ///   <para>Get current process' primary token create a lowbox token with a named package and the internetClient and readRegistry capabilities.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtToken -Session</code>
    ///   <para>Get current session token.</para>
    /// </example>
    /// <example>
    ///   <code>Get-NtToken -Session -SessionId 10</code>
    ///   <para>Get session token for session 10.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.Get, "NtToken", DefaultParameterSetName = "Primary")]
    [OutputType(typeof(NtToken))]
    public sealed class GetNtTokenCmdlet : PSCmdlet
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
        [Parameter(ParameterSetName = "Primary")]
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
        /// <para type="description">Specify the token should be a pseudo token. When set you can't use the object for anything other than queries.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Primary"), Parameter(ParameterSetName = "Impersonation"), Parameter(ParameterSetName = "Effective")]
        public SwitchParameter Pseduo { get; set; }

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
        /// <para type="description">Specify password for logon token using a secure string. Note this isn't really secure, but useful for Read-Host -AsSecureString.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Logon")]
        public SecureString SecurePassword { get; set; }

        /// <summary>
        /// <para type="description">Specify additional group sids for logon token. Needs TCB privilege.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Logon"), Parameter(ParameterSetName = "Service")]
        public Sid[] AdditionalGroups { get; set; }

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
        /// <para type="description">Get a lowbox token.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "LowBox")]
        public SwitchParameter LowBox { get; set; }

        /// <summary>
        /// <para type="description">Get a filtered token.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "Filtered")]
        public SwitchParameter Filtered { get; set; }

        /// <summary>
        /// <para type="description">Specify the token to sandbox. If not specified then the current primary token is used.</para>
        /// </summary>
        [Parameter(ParameterSetName = "LowBox"), Parameter(ParameterSetName = "Filtered")]
        public NtToken Token { get; set; }

        /// <summary>
        /// <para type="description">Specify list of privileges to delete.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Filtered")]
        public TokenPrivilege[] PrivilegesToDelete { get; set; }

        /// <summary>
        /// <para type="description">Specify list group SIDS to disable.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Filtered")]
        public UserGroup[] SidsToDisable { get; set; }

        /// <summary>
        /// <para type="description">Specify list restricted SIDS to add to token.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Filtered")]
        public UserGroup[] RestrictedSids { get; set; }

        /// <summary>
        /// <para type="description">Specify filter flags.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Filtered")]
        public FilterTokenFlags Flags { get; set; }

        /// <summary>
        /// <para type="description">Specify package SID or a package name.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "LowBox")]
        public string PackageSid { get; set; }

        /// <summary>
        /// <para type="description">Specify an additional restricted name for the package SID.</para>
        /// </summary>
        [Parameter(ParameterSetName = "LowBox")]
        public string RestrictedPackageName { get; set; }

        /// <summary>
        /// <para type="description">Specify list of capability SIDS to add to token. Can specify an SDDL format string or a capability name.</para>
        /// </summary>
        [Parameter(ParameterSetName = "LowBox")]
        public string[] CapabilitySids { get; set; }

        /// <summary>
        /// <para type="description">Specify list of handles to capture with lowbox token.</para>
        /// </summary>
        [Parameter(ParameterSetName = "LowBox")]
        public NtObject[] Handles { get; set; }

        /// <summary>
        /// <para type="description">Specify a service account to create.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Service", Mandatory = true)]
        public ServiceAccountType? Service { get; set; }

        /// <summary>
        /// <para type="description">Specify getting a session token.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Session", Mandatory = true)]
        public SwitchParameter Session { get; set; }

        /// <summary>
        /// <para type="description">Specify the session ID for the session token.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Session")]
        public int SessionId { get; set; }

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
        /// Constructor.
        /// </summary>
        public GetNtTokenCmdlet()
        {
            Access = TokenAccessRights.MaximumAllowed;
            TokenType = TokenType.Impersonation;
            ImpersonationLevel = SecurityImpersonationLevel.Impersonation;
            try
            {
                Domain = Environment.UserDomainName;
            }
            catch (InvalidOperationException)
            {
                Domain = "Unknown";
            }
            LogonType = SecurityLogonType.Network;
            SessionId = -1;
        }

        private NtToken GetPrimaryToken(TokenAccessRights desired_access)
        {
            if (Pseduo)
            {
                return NtToken.PseudoPrimaryToken;
            }
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
            if (Pseduo)
            {
                return NtToken.PseudoImpersonationToken;
            }
            if (ThreadId.HasValue)
            {
                return NtToken.OpenThreadToken(ThreadId.Value, OpenAsSelf, false, desired_access);
            }

            return NtToken.OpenThreadToken(Thread ?? NtThread.Current, OpenAsSelf, false, desired_access);
        }

        private NtToken GetEffectiveToken(TokenAccessRights desired_access)
        {
            if (Pseduo)
            {
                return NtToken.PseudoEffectiveToken;
            }
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

        private string GetPassword()
        {
            if (Password != null)
            {
                return Password;
            }

            if (SecurePassword != null)
            {
                IntPtr str = Marshal.SecureStringToBSTR(SecurePassword);
                try
                {
                    return Marshal.PtrToStringBSTR(str);
                }
                finally
                {
                    if (str != IntPtr.Zero)
                    {
                        Marshal.FreeBSTR(str);
                    }
                }
            }

            return null;
        }

        private NtToken GetLogonToken(TokenAccessRights desired_access, string user, 
            string domain, string password, SecurityLogonType logon_type)
        {
            IEnumerable<UserGroup> groups = null;
            if (AdditionalGroups != null && AdditionalGroups.Length > 0)
            {
                groups = AdditionalGroups.Select(s => new UserGroup(s,
                    GroupAttributes.Enabled | GroupAttributes.EnabledByDefault | GroupAttributes.Mandatory));
            }
            using (NtToken token = TokenUtils.GetLogonUserToken(user, domain, password, logon_type, groups))
            {
                if (desired_access == TokenAccessRights.MaximumAllowed)
                {
                    return token.Duplicate();
                }
                return token.Duplicate(desired_access);
            }
        }

        private NtToken GetLogonToken(TokenAccessRights desired_access)
        {
            return GetLogonToken(desired_access, User, Domain, GetPassword(), LogonType);
        }

        private NtToken GetS4UToken(TokenAccessRights desired_access)
        {
            using (NtToken token = LogonUtils.LogonS4U(User, Domain, LogonType))
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

        private NtToken GetSandboxedToken(TokenAccessRights desired_access, Func<NtToken, NtToken> sandbox_func)
        {
            using (NtToken token = Token != null ? Token.Duplicate() : NtToken.OpenProcessToken())
            {
                using (NtToken sandbox_token = sandbox_func(token))
                {
                    if (desired_access == TokenAccessRights.MaximumAllowed)
                    {
                        return sandbox_token.Duplicate();
                    }
                    return sandbox_token.Duplicate(desired_access);
                }
            }
        }

        private NtToken GetLowBoxToken(NtToken token)
        {
            Sid package_sid = TokenUtils.GetPackageSidFromName(PackageSid);
            if (!NtSecurity.IsPackageSid(package_sid))
            {
                throw new ArgumentException($"Invalid Package Sid {package_sid}");
            }

            if (!string.IsNullOrEmpty(RestrictedPackageName))
            {
                package_sid = TokenUtils.DeriveRestrictedPackageSidFromSid(package_sid, RestrictedPackageName);
            }

            IEnumerable<Sid> capability_sids = CapabilitySids == null ? new Sid[0] : CapabilitySids.Select(s =>
                {
                    if (!s.StartsWith("S-"))
                    {
                        return NtSecurity.GetCapabilitySid(s);
                    }
                    Sid sid = new Sid(s);
                    if (!NtSecurity.IsCapabilitySid(sid))
                    {
                        throw new ArgumentException($"{s} is not a capability SID", s);
                    }
                    return sid;
                }
            );
                
            return token.CreateLowBoxToken(package_sid, capability_sids, Handles ?? new NtObject[0], TokenAccessRights.MaximumAllowed);
        }

        private NtToken GetFilteredToken(NtToken token)
        {
            return token.Filter(Flags, GroupsToSids(SidsToDisable),
                GetPrivileges(PrivilegesToDelete), GroupsToSids(RestrictedSids));
        }

        private NtToken GetServiceToken(TokenAccessRights desired_access, ServiceAccountType service_type)
        {
            string user = string.Empty;
            switch (service_type)
            {
                case ServiceAccountType.System:
                    user = "SYSTEM";
                    break;
                case ServiceAccountType.LocalService:
                    user = "Local Service";
                    break;
                case ServiceAccountType.NetworkService:
                    user = "Network Service";
                    break;
            }
            return GetLogonToken(desired_access, user, "NT AUTHORITY", null, SecurityLogonType.Service);
        }

        private NtToken GetSessionToken(TokenAccessRights desired_access, int session_id)
        {
            if (session_id < 0)
            {
                session_id = NtProcess.Current.SessionId;
            }
            using (var token = TokenUtils.GetSessionToken(session_id))
            {
                if (desired_access == TokenAccessRights.MaximumAllowed)
                {
                    return token.Duplicate();
                }
                return token.Duplicate(desired_access);
            }
        }

        private NtToken GetToken(TokenAccessRights desired_access)
        {
            if (Impersonation)
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
            else if (LowBox)
            {
                return GetSandboxedToken(desired_access, GetLowBoxToken);
            }
            else if (Filtered)
            {
                return GetSandboxedToken(desired_access, GetFilteredToken);
            }
            else if (Service.HasValue)
            {
                return GetServiceToken(desired_access, Service.Value);
            }
            else if (Session)
            {
                return GetSessionToken(desired_access, SessionId);
            }
            else
            {
                // The default is primary token.
                return GetPrimaryToken(desired_access);
            }
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
                    if (base_token != null)
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
            }
            else
            {
                token = GetToken(Access);
            }
            WriteObject(token);
        }
    }

    /// <summary>
    /// <para type="synopsis">Create a new NT token.</para>
    /// <para type="description">This cmdlet creates a new NT token kernel APIs. It needs SeCreateTokenPrivilege to succeed.</para>
    /// </summary>
    /// <example>
    ///   <code>$token = New-NtToken -User "SY"</code>
    ///   <para>Create a new LocalSystem token with no groups or privileges.</para>
    /// </example>
    /// <example>
    ///   <code>$token = New-NtToken -User "SY" -Groups "BA","WD" -Privileges SeDebugPrivilege,SeImpersonatePrivilege</code>
    ///   <para>Create a new LocalSystem token with two groups and two privileges.</para>
    /// </example>
    /// <para type="link">about_ManagingNtObjectLifetime</para>
    [Cmdlet(VerbsCommon.New, "NtToken")]
    [OutputType(typeof(NtToken))]
    public sealed class NewNtTokenCmdlet : NtObjectBaseCmdletWithAccess<TokenAccessRights>
    {
        /// <summary>
        /// <para type="description">Specify the user SID.</para>
        /// </summary>
        [Parameter(Mandatory = true)]
        public Sid User { get; set; }

        /// <summary>
        /// <para type="description">Specify a list of groups.</para>
        /// </summary>
        [Parameter]
        public Sid[] Groups { get; set; }

        /// <summary>
        /// <para type="description">Specify a list of groups.</para>
        /// </summary>
        [Parameter]
        public TokenPrivilegeValue[] Privileges { get; set; }

        /// <summary>
        /// <para type="description">Specify an authentication ID.</para>
        /// </summary>
        [Parameter]
        public Luid AuthenticationId { get; set; }

        /// <summary>
        /// <para type="description">Specify the token type.</para>
        /// </summary>
        [Parameter]
        public TokenType TokenType { get; set; }

        /// <summary>
        /// <para type="description">Specify the token expiration time.</para>
        /// </summary>
        [Parameter]
        public DateTime ExpirationTime { get; set; }

        /// <summary>
        /// <para type="description">Specify the token's default ACL.</para>
        /// </summary>
        [Parameter]
        public Acl DefaultAcl { get; set; }

        /// <summary>
        /// <para type="description">Specify the token's integrity level.</para>
        /// </summary>
        [Parameter]
        public TokenIntegrityLevel IntegrityLevel { get; set; }

        /// <summary>
        /// Determine if the cmdlet can create objects.
        /// </summary>
        /// <returns>True if objects can be created.</returns>
        protected override bool CanCreateDirectories()
        {
            return false;
        }

        private IEnumerable<UserGroup> GetGroups()
        {
            List<UserGroup> groups = Groups.Select(g => new UserGroup(g, GroupAttributes.Enabled | GroupAttributes.EnabledByDefault | GroupAttributes.Mandatory)).ToList();
            groups.Add(new UserGroup(NtSecurity.GetIntegritySid(IntegrityLevel), GroupAttributes.Integrity | GroupAttributes.IntegrityEnabled));
            return groups;
        }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            return NtToken.Create(Access, obj_attributes, TokenType, AuthenticationId, ExpirationTime.ToFileTimeUtc(), new UserGroup(User, GroupAttributes.Owner),
                GetGroups(), Privileges.Select(p => new TokenPrivilege(p, PrivilegeAttributes.EnabledByDefault | PrivilegeAttributes.Enabled)),
                User, User, DefaultAcl, "NT.NET");
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        public NewNtTokenCmdlet()
        {
            AuthenticationId = NtToken.LocalSystemAuthId;
            TokenType = TokenType.Primary;
            ExpirationTime = DateTime.Now.AddYears(10);
            Groups = new Sid[0];
            Privileges = new TokenPrivilegeValue[0];
            DefaultAcl = new Acl();
            DefaultAcl.AddAccessAllowedAce(GenericAccessRights.GenericAll, AceFlags.None, "SY");
            DefaultAcl.AddAccessAllowedAce(GenericAccessRights.GenericAll, AceFlags.None, "BA");
            IntegrityLevel = TokenIntegrityLevel.System;
            SecurityQualityOfService = new SecurityQualityOfService(SecurityImpersonationLevel.Anonymous, SecurityContextTrackingMode.Static, false);
        }
    }

    /// <summary>
    /// <para type="synopsis">Adds or replaces security attributes on an NT token.</para>
    /// <para type="description">This cmdlet adds or replaces security attributes on an NT token. It needs SeTcbPrivilege to succeed.</para>
    /// </summary>
    /// <example>
    ///   <code>Add-NtTokenSecurityAttribute -Token $token -Name "TEST://ME" -String "ABC"</code>
    ///   <para>Adds the security attribute TEST://ME with the string value "ABC".</para>
    /// </example>
    [Cmdlet(VerbsCommon.Add, "NtTokenSecurityAttribute")]
    public sealed class AddNtTokenSecurityAttribute : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the token to set the attributes on.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public NtToken Token { get; set; }

        /// <summary>
        /// <para type="description">Specify the name of the attribute to add or update.</para>
        /// </summary>
        [Parameter(Position = 1, Mandatory = true, ParameterSetName = "FromString")]
        [Parameter(Position = 1, Mandatory = true, ParameterSetName = "FromULong")]
        [Parameter(Position = 1, Mandatory = true, ParameterSetName = "FromLong")]
        [Parameter(Position = 1, Mandatory = true, ParameterSetName = "FromBool")]
        [Parameter(Position = 1, Mandatory = true, ParameterSetName = "FromSid")]
        [Parameter(Position = 1, Mandatory = true, ParameterSetName = "FromFqbn")]
        [Parameter(Position = 1, Mandatory = true, ParameterSetName = "FromOctet")]
        public string Name { get; set; }

        /// <summary>
        /// <para type="description">Specify the attribute flags.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromString")]
        [Parameter(ParameterSetName = "FromULong")]
        [Parameter(ParameterSetName = "FromLong")]
        [Parameter(ParameterSetName = "FromBool")]
        [Parameter(ParameterSetName = "FromSid")]
        [Parameter(ParameterSetName = "FromFqbn")]
        [Parameter(ParameterSetName = "FromOctet")]
        public ClaimSecurityFlags Flags { get; set; }

        /// <summary>
        /// <para type="description">Specify to replace the security attribute.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromString")]
        [Parameter(ParameterSetName = "FromULong")]
        [Parameter(ParameterSetName = "FromLong")]
        [Parameter(ParameterSetName = "FromBool")]
        [Parameter(ParameterSetName = "FromSid")]
        [Parameter(ParameterSetName = "FromFqbn")]
        [Parameter(ParameterSetName = "FromOctet")]
        [Parameter(ParameterSetName = "FromAttribute")]
        public SwitchParameter Replace { get; set; }

        /// <summary>
        /// <para type="description">Specify the string values.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromString")]
        public string[] StringValue { get; set; }

        /// <summary>
        /// <para type="description">Specify the ulong values.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromULong")]
        public ulong[] ULongValue { get; set; }

        /// <summary>
        /// <para type="description">Specify the long values.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromLong")]
        public long[] LongValue { get; set; }

        /// <summary>
        /// <para type="description">Specify the bool values.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromBool")]
        public bool[] BoolValue { get; set; }

        /// <summary>
        /// <para type="description">Specify the SID values.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromSid")]
        public Sid[] SidValue { get; set; }

        /// <summary>
        /// <para type="description">Specify the fully qualified binary name values.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromFqbn")]
        public ClaimSecurityAttributeFqbn[] FqbnValue { get; set; }

        /// <summary>
        /// <para type="description">Specify the octet values.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromOctet")]
        public byte[][] OctetValue { get; set; }

        /// <summary>
        /// <para type="description">Specify existing attribute values.</para>
        /// </summary>
        [Parameter(ParameterSetName = "FromAttribute")]
        public ClaimSecurityAttribute[] Attribute { get; set; }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            List<ClaimSecurityAttributeBuilder> builders = new List<ClaimSecurityAttributeBuilder>();
            List<TokenSecurityAttributeOperation> ops = new List<TokenSecurityAttributeOperation>();
            if (Attribute != null)
            {
                builders.AddRange(Attribute.Select(a => a.ToBuilder()));
                var op = Replace ? TokenSecurityAttributeOperation.Replace : TokenSecurityAttributeOperation.Add;
                ops.AddRange(Enumerable.Repeat(op, Attribute.Length));
            }
            else
            {
                builders.Add(CreateBuilder());
                ops.Add(Replace ? TokenSecurityAttributeOperation.Replace : TokenSecurityAttributeOperation.Add);
            }

            Token.SetSecurityAttributes(builders, ops);
        }

        private ClaimSecurityAttributeBuilder CreateBuilder()
        {
            if (StringValue != null)
            {
                return ClaimSecurityAttributeBuilder.Create(Name, Flags, StringValue);
            }
            else if (ULongValue != null)
            {
                return ClaimSecurityAttributeBuilder.Create(Name, Flags, ULongValue);
            }
            else if (LongValue != null)
            {
                return ClaimSecurityAttributeBuilder.Create(Name, Flags, LongValue);
            }
            else if (BoolValue != null)
            {
                return ClaimSecurityAttributeBuilder.Create(Name, Flags, BoolValue);
            }
            else if (SidValue != null)
            {
                return ClaimSecurityAttributeBuilder.Create(Name, Flags, SidValue);
            }
            else if (FqbnValue != null)
            {
                return ClaimSecurityAttributeBuilder.Create(Name, Flags, FqbnValue);
            }
            else if (OctetValue != null)
            {
                return ClaimSecurityAttributeBuilder.Create(Name, Flags, OctetValue);
            }

            throw new ArgumentException("Invalid security attribute type");
        }
    }

    /// <summary>
    /// <para type="synopsis">Removes security attributes on an NT token.</para>
    /// <para type="description">This cmdlet removes security attributes on an NT token. It needs SeTcbPrivilege to succeed.</para>
    /// </summary>
    /// <example>
    ///   <code>Remove-NtTokenSecurityAttribute -Token $token -Name "TEST://ME"</code>
    ///   <para>Removes the security attribute TEST://ME.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Remove, "NtTokenSecurityAttribute")]
    public sealed class RemoveNtTokenSecurityAttribute : PSCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the token to set the attributes on.</para>
        /// </summary>
        [Parameter(Position = 0, Mandatory = true)]
        public NtToken Token { get; set; }

        /// <summary>
        /// <para type="description">Specify the name of the attributes to remove.</para>
        /// </summary>
        [Parameter(Position = 1, Mandatory = true, ParameterSetName = "FromName")]
        public string[] Name { get; set; }

        /// <summary>
        /// <para type="description">Specify existing attribute values.</para>
        /// </summary>
        [Parameter(Position = 1, Mandatory = true, ParameterSetName = "FromAttribute")]
        public ClaimSecurityAttribute[] Attribute { get; set; }

        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            if (Attribute != null)
            {
                Name = Attribute.Select(a => a.Name).ToArray();
            }
            
            var builders = Name.Select(n => ClaimSecurityAttributeBuilder.Create(n, 0, new long[0]));
            var ops = Enumerable.Repeat(TokenSecurityAttributeOperation.Delete, Name.Length);
            Token.SetSecurityAttributes(builders, ops);
        }
    }
}
