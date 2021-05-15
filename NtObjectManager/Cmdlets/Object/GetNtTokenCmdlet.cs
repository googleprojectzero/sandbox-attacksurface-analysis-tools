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
using NtApiDotNet.Win32;
using NtApiDotNet.Win32.Security;
using NtApiDotNet.Win32.Security.Authentication;
using NtApiDotNet.Win32.Security.Authentication.Kerberos;
using NtApiDotNet.Win32.Security.Native;
using NtObjectManager.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Security;

namespace NtObjectManager.Cmdlets.Object
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
        NetworkService,
        /// <summary>
        /// Create IUsr Service token.
        /// </summary>
        IUsr,
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
        [Parameter(ParameterSetName = "Primary"), Parameter(ParameterSetName = "Impersonation"), Parameter(ParameterSetName = "Effective"), Alias("Pseduo")]
        public SwitchParameter Pseudo { get; set; }

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
        /// <para type="description">Specify logon provider.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Logon")]
        public Logon32Provider LogonProvider { get; set; }

        /// <summary>
        /// <para type="description">Specify to use SeTcbPrivilege for the logon. This might require finding a token to steal.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Logon")]
        [Parameter(ParameterSetName = "Service")]
        [Parameter(ParameterSetName = "S4U")]
        [Parameter(ParameterSetName = "Session")]
        public SwitchParameter WithTcb { get; set; }

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
        /// <para type="description">Specify password for logon token. Can be a string or a secure string.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Logon")]
        [Alias("SecurePassword")]
        public PasswordHolder Password { get; set; }

        /// <summary>
        /// <para type="description">Specify additional group sids for logon token. Needs TCB privilege.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Logon"), 
            Parameter(ParameterSetName = "Service")]
        [Alias("AdditionalGroups")]
        public Sid[] AdditionalGroup { get; set; }

        /// <summary>
        /// <para type="description">Specify domain for logon token.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Logon"), Parameter(ParameterSetName = "S4U")]
        public string Domain { get; set; }

        /// <summary>
        /// <para type="description">Specify logon type for logon token.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Logon"), Parameter(ParameterSetName = "S4U"), Parameter(ParameterSetName = "Ticket")]
        public SecurityLogonType LogonType { get; set; }

        /// <summary>
        /// <para type="description">Specify Service Ticket for Logon.</para>
        /// </summary>
        [Parameter(Position = 0, ParameterSetName = "Ticket", Mandatory = true)]
        public KerberosTicket Ticket { get; }

        /// <summary>
        /// <para type="description">Specify optional TGT for logon.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Ticket", Mandatory = true)]
        public KerberosCredential KerbCred { get; }

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
        /// <para type="description">Get a AppContainer token. This creates all the necessary directories for the AppContainer.</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = "AppContainer")]
        public SwitchParameter AppContainer { get; set; }

        /// <summary>
        /// <para type="description">Specify the token to sandbox or query. If not specified then the current primary token is used.</para>
        /// </summary>
        [Parameter(ParameterSetName = "LowBox"), 
         Parameter(ParameterSetName = "Filtered"), 
         Parameter(ParameterSetName = "AppContainer"),
         Parameter(ParameterSetName = "Linked")]
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
        [Parameter(Mandatory = true, ParameterSetName = "LowBox"), Parameter(ParameterSetName = "AppContainer")]
        public string PackageSid { get; set; }

        /// <summary>
        /// <para type="description">Specify an additional restricted name for the package SID.</para>
        /// </summary>
        [Parameter(ParameterSetName = "LowBox"), Parameter(ParameterSetName = "AppContainer")]
        public string RestrictedPackageName { get; set; }

        /// <summary>
        /// <para type="description">Specify list of capability SIDS to add to token. Can specify an SDDL format string or a capability name.</para>
        /// </summary>
        [Parameter(ParameterSetName = "LowBox"), Parameter(ParameterSetName = "AppContainer")]
        [Alias("CapabilitySids")]
        public string[] CapabilitySid { get; set; }

        /// <summary>
        /// <para type="description">Specify list of handles to capture with lowbox token.</para>
        /// </summary>
        [Parameter(ParameterSetName = "LowBox")]
        [Alias("Handles")]
        public NtObject[] Handle { get; set; }

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

        /// <summary>
        /// <para type="description">Specify to get the linked token.</para>
        /// </summary>
        [Parameter(ParameterSetName = "Linked", Mandatory = true)]
        public SwitchParameter Linked { get; set; }

        /// <summary>
        /// <para type="description">Specify to get the linked token.</para>
        /// </summary>
        [Parameter(ParameterSetName = "ServiceName", Mandatory = true)]
        public string ServiceName { get; set; }

        private static IEnumerable<Luid> GetPrivileges(IEnumerable<TokenPrivilege> privs)
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
            if (Pseudo)
            {
                return NtToken.PseudoPrimaryToken;
            }
            if (ProcessId.HasValue)
            {
                return NtToken.OpenProcessToken(ProcessId.Value, false, desired_access);
            }

            return NtToken.OpenProcessToken(Process ?? NtProcess.Current, false, desired_access);
        }

        private NtToken GetServiceNameToken(TokenAccessRights desired_access)
        {
            int pid = ServiceUtils.GetServiceProcessId(ServiceName);
            if (pid == 0)
            {
                throw new ArgumentException($"{ServiceName} is not current running.");
            }
            using (var process = NtProcess.Open(pid, ProcessAccessRights.QueryLimitedInformation))
            {
                return NtToken.OpenProcessToken(process, false, desired_access);
            }
        }

        private static NtToken GetClipboardToken(TokenAccessRights desired_access)
        {
            return TokenUtils.GetTokenFromClipboard(desired_access);
        }

        private NtToken GetImpersonationToken(TokenAccessRights desired_access)
        {
            if (Pseudo)
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
            if (Pseudo)
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

        private static GroupAttributes GetAttributes(Sid sid)
        {
            if (NtSecurity.IsServiceSid(sid))
            {
                return GroupAttributes.Owner | GroupAttributes.Enabled;
            }
            else if (NtSecurity.IsLogonSessionSid(sid))
            {
                return GroupAttributes.Enabled | GroupAttributes.EnabledByDefault | GroupAttributes.Mandatory | GroupAttributes.LogonId;
            }
            return GroupAttributes.Enabled | GroupAttributes.EnabledByDefault | GroupAttributes.Mandatory;
        }

        private NtToken GetLogonToken(TokenAccessRights desired_access, string user, 
            string domain, SecureString password, SecurityLogonType logon_type)
        {
            IEnumerable<UserGroup> groups = null;
            if (AdditionalGroup != null && AdditionalGroup.Length > 0)
            {
                groups = AdditionalGroup.Select(s => new UserGroup(s,
                    GetAttributes(s)));
            }
            using (NtToken token = Win32Security.LsaLogonUser(user, domain, password, logon_type, LogonProvider, groups))
            {
                if (desired_access == TokenAccessRights.MaximumAllowed)
                {
                    return token.Duplicate();
                }
                return token.Duplicate(desired_access);
            }
        }

        private ThreadImpersonationContext GetTcbPrivilege()
        {
            if (!WithTcb)
                return null;
            if (NtToken.EnableEffectivePrivilege(TokenPrivilegeValue.SeTcbPrivilege))
            {
                return null;
            }

            return PSUtils.ImpersonateSystem();
        }

        private NtToken GetLogonToken(TokenAccessRights desired_access)
        {
            using (GetTcbPrivilege())
            {
                return GetLogonToken(desired_access, User, Domain, Password?.Password, LogonType);
            }
        }

        private NtToken GetS4UToken(TokenAccessRights desired_access)
        {
            using (GetTcbPrivilege())
            {
                using (NtToken token = LogonUtils.LsaLogonS4U(User, Domain, LogonType, AuthenticationPackage.NEGOSSP_NAME))
                {
                    if (desired_access == TokenAccessRights.MaximumAllowed)
                    {
                        return token.Duplicate();
                    }
                    return token.Duplicate(desired_access);
                }
            }
        }

        private NtToken GetTicketToken(TokenAccessRights desired_access)
        {
            using (GetTcbPrivilege())
            {
                using (NtToken token = LogonUtils.LsaLogonTicket(LogonType, Ticket, KerbCred))
                {
                    if (desired_access == TokenAccessRights.MaximumAllowed)
                    {
                        return token.Duplicate();
                    }
                    return token.Duplicate(desired_access);
                }
            }
        }

        private static NtToken GetAnonymousToken(TokenAccessRights desired_access)
        {
            return TokenUtils.GetAnonymousToken(desired_access);
        }

        private NtToken GetRelatedToken(TokenAccessRights desired_access, Func<NtToken, NtToken> sandbox_func)
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

        private IEnumerable<Sid> GetCapabilitySids()
        {
            return CapabilitySid == null ? new Sid[0] : CapabilitySid.Select(s =>
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

            if (AppContainer)
            {
                return TokenUtils.CreateAppContainerToken(token, package_sid, GetCapabilitySids());
            }

            return token.CreateLowBoxToken(package_sid, GetCapabilitySids(), 
                Handle ?? new NtObject[0], TokenAccessRights.MaximumAllowed);
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
                case ServiceAccountType.IUsr:
                    user = "IUsr";
                    break;
            }
            using (GetTcbPrivilege())
            {
                return GetLogonToken(desired_access, user, "NT AUTHORITY", null, SecurityLogonType.Service);
            }
        }

        private NtToken GetSessionToken(TokenAccessRights desired_access, int session_id)
        {
            using (var imp = GetTcbPrivilege())
            {
                if (imp == null)
                {
                    WriteWarning("Getting session token requires SeTcbPrivilege");
                }

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
            else if (Ticket != null)
            {
                return GetTicketToken(desired_access);
            }
            else if (Anonymous)
            {
                return GetAnonymousToken(desired_access);
            }
            else if (LowBox || AppContainer)
            {
                return GetRelatedToken(desired_access, GetLowBoxToken);
            }
            else if (Filtered)
            {
                return GetRelatedToken(desired_access, GetFilteredToken);
            }
            else if (Service.HasValue)
            {
                return GetServiceToken(desired_access, Service.Value);
            }
            else if (Session)
            {
                return GetSessionToken(desired_access, SessionId);
            }
            else if (Linked)
            {
                return GetRelatedToken(desired_access, t => t.GetLinkedToken());
            }
            else if (ServiceName != null)
            {
                return GetServiceNameToken(desired_access);
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
                if (IntegrityLevel.HasValue)
                {
                    WriteWarning("Must specify Duplicate with IntegrityLevel.");
                }
                token = GetToken(Access);
            }
            WriteObject(token);
        }
    }
}
