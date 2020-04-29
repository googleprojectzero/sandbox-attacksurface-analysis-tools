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

using NtApiDotNet.Win32.SafeHandles;
using NtApiDotNet.Win32.Security.Authentication;
using NtApiDotNet.Win32.Security.Native;
using NtApiDotNet.Win32.Security.Policy;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Logon type
    /// </summary>
    public enum SecurityLogonType
    {
        /// <summary>
        /// This is used to specify an undefined logon type
        /// </summary>
        UndefinedLogonType = 0,
        /// <summary>
        /// Interactively logged on (locally or remotely)
        /// </summary>
        Interactive = 2,
        /// <summary>
        /// Accessing system via network
        /// </summary>
        Network,
        /// <summary>
        /// Started via a batch queue
        /// </summary>
        Batch,
        /// <summary>
        /// Service started by service controller
        /// </summary>
        Service,
        /// <summary>
        /// Proxy logon
        /// </summary>
        Proxy,
        /// <summary>
        /// Unlock workstation
        /// </summary>
        Unlock,
        /// <summary>
        /// Network logon with cleartext credentials
        /// </summary>
        NetworkCleartext,
        /// <summary>
        /// Clone caller, new default credentials
        /// </summary>
        NewCredentials,
        /// <summary>
        /// Remove interactive.
        /// </summary>
        RemoteInteractive,
        /// <summary>
        /// Cached Interactive.
        /// </summary>
        CachedInteractive,
        /// <summary>
        /// Cached Remote Interactive.
        /// </summary>
        CachedRemoteInteractive,
        /// <summary>
        /// Cached unlock.
        /// </summary>
        CachedUnlock
    }

    /// <summary>
    /// Specify what account rights to get.
    /// </summary>
    public enum AccountRightType
    {
        /// <summary>
        /// Get all account rights.
        /// </summary>
        All,
        /// <summary>
        /// Get all privilege account rights.
        /// </summary>
        Privilege,
        /// <summary>
        /// Get logon account rights.
        /// </summary>
        Logon
    }

    /// <summary>
    /// Utilities for user logon.
    /// </summary>
    public static class LogonUtils
    {
        /// <summary>
        /// Logon a user with a username and password.
        /// </summary>
        /// <param name="user">The username.</param>
        /// <param name="domain">The user's domain.</param>
        /// <param name="password">The user's password.</param>
        /// <param name="type">The type of logon token.</param>
        /// <returns>The logged on token.</returns>
        public static NtToken Logon(string user, string domain, string password, SecurityLogonType type)
        {
            if (!SecurityNativeMethods.LogonUser(user, domain, password, type, 0, out SafeKernelObjectHandle handle))
            {
                throw new SafeWin32Exception();
            }
            return NtToken.FromHandle(handle);
        }

        /// <summary>
        /// Logon a user with a username and password.
        /// </summary>
        /// <param name="user">The username.</param>
        /// <param name="domain">The user's domain.</param>
        /// <param name="password">The user's password.</param>
        /// <param name="type">The type of logon token.</param>
        /// <param name="groups">Additional groups to add. Needs SeTcbPrivilege.</param>
        /// <returns>The logged on token.</returns>
        public static NtToken Logon(string user, string domain, string password, SecurityLogonType type, IEnumerable<UserGroup> groups)
        {
            TokenGroupsBuilder builder = new TokenGroupsBuilder();
            foreach (var group in groups)
            {
                builder.AddGroup(group.Sid, group.Attributes);
            }

            using (var group_buffer = builder.ToBuffer())
            {
                if (!SecurityNativeMethods.LogonUserExExW(user, domain, password, type, 0, group_buffer, 
                    out SafeKernelObjectHandle token, null, null, null, null))
                {
                    throw new SafeWin32Exception();
                }
                return new NtToken(token);
            }
        }

        /// <summary>
        /// Logon user using Kerberos Ticket.
        /// </summary>
        /// <param name="type">The type of logon token.</param>
        /// <param name="service_ticket">The service ticket.</param>
        /// <param name="tgt_ticket">Optional TGT.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The logged on token.</returns>
        public static NtResult<NtToken> LsaLogonTicket(SecurityLogonType type, byte[] service_ticket, byte[] tgt_ticket, bool throw_on_error)
        {
            if (service_ticket is null)
            {
                throw new ArgumentNullException(nameof(service_ticket));
            }
            int total_size = service_ticket.Length + (tgt_ticket?.Length ?? 0);

            using (var buffer = new SafeStructureInOutBuffer<KERB_TICKET_LOGON>(total_size, true))
            {
                KERB_TICKET_LOGON logon_struct = new KERB_TICKET_LOGON
                {
                    MessageType = KERB_LOGON_SUBMIT_TYPE.KerbTicketLogon,
                    ServiceTicketLength = service_ticket.Length,
                    ServiceTicket = buffer.Data.DangerousGetHandle(),
                    TicketGrantingTicket = tgt_ticket != null ? buffer.Data.DangerousGetHandle() + service_ticket.Length : IntPtr.Zero,
                    TicketGrantingTicketLength = tgt_ticket?.Length ?? 0
                };
                buffer.Data.WriteArray(0, service_ticket, 0, service_ticket.Length);
                if (tgt_ticket != null)
                {
                    buffer.Data.WriteArray((ulong)service_ticket.Length, tgt_ticket, 0, tgt_ticket.Length);
                }

                buffer.Result = logon_struct;
                return LsaLogonUser(type, AuthenticationPackage.KERBEROS_NAME, "KTIK", buffer, null, throw_on_error);
            }
        }

        /// <summary>
        /// Logon user using Kerberos Ticket.
        /// </summary>
        /// <param name="type">The type of logon token.</param>
        /// <param name="service_ticket">The service ticket.</param>
        /// <param name="tgt_ticket">Optional TGT.</param>
        /// <returns>The logged on token.</returns>
        public static NtToken LsaLogonTicket(SecurityLogonType type, byte[] service_ticket, byte[] tgt_ticket)
        {
            return LsaLogonTicket(type, service_ticket, tgt_ticket, true).Result;
        }

        /// <summary>
        /// Logon user using S4U
        /// </summary>
        /// <param name="user">The username.</param>
        /// <param name="realm">The user's realm.</param>
        /// <param name="type">The type of logon token.</param>
        /// <param name="auth_package">The name of the auth package to user.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The logged on token.</returns>
        public static NtResult<NtToken> LsaLogonS4U(string user, string realm, SecurityLogonType type, string auth_package, bool throw_on_error)
        {
            if (user is null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (realm is null)
            {
                throw new ArgumentNullException(nameof(realm));
            }

            byte[] user_bytes = Encoding.Unicode.GetBytes(user);
            byte[] realm_bytes = Encoding.Unicode.GetBytes(realm);

            using (var buffer = new SafeStructureInOutBuffer<KERB_S4U_LOGON>(user_bytes.Length + realm_bytes.Length, true))
            {
                KERB_S4U_LOGON logon_struct = new KERB_S4U_LOGON
                {
                    MessageType = KERB_LOGON_SUBMIT_TYPE.KerbS4ULogon
                };
                SafeHGlobalBuffer data_buffer = buffer.Data;

                logon_struct.ClientUpn.Buffer = data_buffer.DangerousGetHandle();
                data_buffer.WriteArray(0, user_bytes, 0, user_bytes.Length);
                logon_struct.ClientUpn.Length = (ushort)user_bytes.Length;
                logon_struct.ClientUpn.MaximumLength = (ushort)user_bytes.Length;

                logon_struct.ClientRealm.Buffer = data_buffer.DangerousGetHandle() + user_bytes.Length;
                data_buffer.WriteArray((ulong)user_bytes.Length, realm_bytes, 0, realm_bytes.Length);
                logon_struct.ClientRealm.Length = (ushort)realm_bytes.Length;
                logon_struct.ClientRealm.MaximumLength = (ushort)realm_bytes.Length;
                buffer.Result = logon_struct;

                return LsaLogonUser(type, auth_package, "S4U", buffer, null, throw_on_error);
            }
        }

        /// <summary>
        /// Logon user using S4U
        /// </summary>
        /// <param name="user">The username.</param>
        /// <param name="realm">The user's realm.</param>
        /// <param name="type">The type of logon token.</param>
        /// <param name="auth_package">The name of the auth package to user.</param>
        /// <returns>The logged on token.</returns>
        public static NtToken LsaLogonS4U(string user, string realm, SecurityLogonType type, string auth_package)
        {
            return LsaLogonS4U(user, realm, type, auth_package, true).Result;
        }

        /// <summary>
        /// Logon user using S4U
        /// </summary>
        /// <param name="user">The username.</param>
        /// <param name="realm">The user's realm.</param>
        /// <param name="type">The type of logon token.</param>
        /// <returns>The logged on token.</returns>
        public static NtToken LsaLogonS4U(string user, string realm, SecurityLogonType type)
        {
            return LsaLogonS4U(user, realm, type, AuthenticationPackage.NEGOSSP_NAME);
        }

        /// <summary>
        /// Logon user using S4U
        /// </summary>
        /// <param name="user">The username.</param>
        /// <param name="realm">The user's realm.</param>
        /// <param name="type">The type of logon token.</param>
        /// <returns>The logged on token.</returns>
        [Obsolete("Use LsaLogonS4U")]
        public static NtToken LogonS4U(string user, string realm, SecurityLogonType type)
        {
            return LsaLogonS4U(user, realm, type);
        }

        /// <summary>
        /// Get a logon session.
        /// </summary>
        /// <param name="luid">The logon session ID.</param>
        /// <param name="throw_on_error">True to thrown on error.</param>
        /// <returns>The logon session.</returns>
        public static NtResult<LogonSession> GetLogonSession(Luid luid, bool throw_on_error)
        {
            return LogonSession.GetLogonSession(luid, throw_on_error);
        }

        /// <summary>
        /// Get a logon session.
        /// </summary>
        /// <param name="luid">The logon session ID.</param>
        /// <returns>The logon session.</returns>
        public static LogonSession GetLogonSession(Luid luid)
        {
            return GetLogonSession(luid, true).Result;
        }

        /// <summary>
        /// Get the logon session LUIDs
        /// </summary>
        /// <param name="throw_on_error">True throw on error.</param>
        /// <returns>The list of logon sessions. Only returns ones you can access.</returns>
        public static NtResult<IEnumerable<Luid>> GetLogonSessionIds(bool throw_on_error)
        {
            return LogonSession.GetLogonSessionIds(throw_on_error);
        }

        /// <summary>
        /// Get the logon session LUIDs
        /// </summary>
        /// <returns>The list of logon sessions. Only returns ones you can access.</returns>
        public static IEnumerable<Luid> GetLogonSessionIds()
        {
            return GetLogonSessionIds(true).Result;
        }

        /// <summary>
        /// Get the logon sessions.
        /// </summary>
        /// <param name="throw_on_error">True throw on error.</param>
        /// <returns>The list of logon sessions. Only returns ones you can access.</returns>
        public static NtResult<IEnumerable<LogonSession>> GetLogonSessions(bool throw_on_error)
        {
            return LogonSession.GetLogonSessions(throw_on_error);
        }

        /// <summary>
        /// Get the logon sessions.
        /// </summary>
        /// <returns>The list of logon sessions.</returns>
        public static IEnumerable<LogonSession> GetLogonSessions()
        {
            return GetLogonSessions(true).Result;
        }

        /// <summary>
        /// Get account rights assigned to a SID.
        /// </summary>
        /// <param name="sid">The SID to query.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of account rights.</returns>
        public static NtResult<IEnumerable<AccountRight>> GetAccountRights(Sid sid, bool throw_on_error)
        {
            return AccountRight.GetAccountRights(null, sid, throw_on_error);
        }

        /// <summary>
        /// Get account rights assigned to a SID.
        /// </summary>
        /// <param name="sid">The SID to query.</param>
        /// <returns>The list of account rights.</returns>
        public static IEnumerable<AccountRight> GetAccountRights(Sid sid)
        {
            return GetAccountRights(sid, true).Result;
        }

        /// <summary>
        /// Get SIDs associated with an account right.
        /// </summary>
        /// <param name="account_right">The name of the account right, such as SeImpersonatePrivilege.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of SIDs assigned to the account right.</returns>
        public static NtResult<IEnumerable<Sid>> GetAccountRightSids(string account_right, bool throw_on_error)
        {
            return AccountRight.GetSids(null, account_right, throw_on_error).Map<IEnumerable<Sid>>(s => s.AsReadOnly());
        }

        /// <summary>
        /// Get SIDs associated with an account right.
        /// </summary>
        /// <param name="account_right">The name of the account right, such as SeImpersonatePrivilege.</param>
        /// <returns>The list of SIDs assigned to the account right.</returns>
        public static IEnumerable<Sid> GetAccountRightSids(string account_right)
        {
            return GetAccountRightSids(account_right, true).Result;
        }

        /// <summary>
        /// Get SIDs associated with an account right.
        /// </summary>
        /// <param name="privilege">The account right privilege to query.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of SIDs assigned to the account right.</returns>
        public static NtResult<IEnumerable<Sid>> GetAccountRightSids(TokenPrivilegeValue privilege, bool throw_on_error)
        {
            return GetAccountRightSids(privilege.ToString(), throw_on_error);
        }

        /// <summary>
        /// Get SIDs associated with an account right.
        /// </summary>
        /// <param name="privilege">The account right privilege to query.</param>
        /// <returns>The list of SIDs assigned to the account right.</returns>
        public static IEnumerable<Sid> GetAccountRightSids(TokenPrivilegeValue privilege)
        {
            return GetAccountRightSids(privilege, true).Result;
        }

        /// <summary>
        /// Get SIDs associated with an account right.
        /// </summary>
        /// <param name="logon_type">The logon account right to query.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of SIDs assigned to the account right.</returns>
        public static NtResult<IEnumerable<Sid>> GetAccountRightSids(AccountRightLogonType logon_type, bool throw_on_error)
        {
            return GetAccountRightSids(logon_type.ToString(), throw_on_error);
        }

        /// <summary>
        /// Get SIDs associated with an account right.
        /// </summary>
        /// <param name="logon_type">The logon account right to query.</param>
        /// <returns>The list of SIDs assigned to the account right.</returns>
        public static IEnumerable<Sid> GetAccountRightSids(AccountRightLogonType logon_type)
        {
            return GetAccountRightSids(logon_type, true).Result;
        }

        /// <summary>
        /// Get account rights.
        /// </summary>
        /// <param name="type">Specify the type of account rights to get.</param>
        /// <returns>Account rights.</returns>
        public static IEnumerable<AccountRight> GetAccountRights(AccountRightType type)
        {
            IEnumerable<string> rights = new string[0];
            if (type == AccountRightType.All || type == AccountRightType.Privilege)
            {
                rights = Enum.GetNames(typeof(TokenPrivilegeValue));
            }
            if (type == AccountRightType.All || type == AccountRightType.Logon)
            {
                rights = rights.Concat(Enum.GetNames(typeof(AccountRightLogonType)));
            }

            return rights.Select(n => new AccountRight(null, n, null)).ToList().AsReadOnly();
        }

        /// <summary>
        /// Get all account rights.
        /// </summary>
        /// <returns>All account rights.</returns>
        public static IEnumerable<AccountRight> GetAccountRights()
        {
            return GetAccountRights(AccountRightType.All);
        }

        private static NtResult<NtToken> LsaLogonUser(SecurityLogonType type, string auth_package, string origin_name, 
            SafeBuffer buffer, IEnumerable<UserGroup> local_groups, bool throw_on_error)
        {
            using (var list = new DisposableList())
            {
                var hlsa = list.AddResource(SafeLsaLogonHandle.Connect(throw_on_error));
                if (!hlsa.IsSuccess)
                    return hlsa.Cast<NtToken>();
                NtStatus status = SecurityNativeMethods.LsaLookupAuthenticationPackage(
                    hlsa.Result, new LsaString(auth_package), out uint auth_pkg);
                if (!status.IsSuccess())
                    return status.CreateResultFromError<NtToken>(throw_on_error);

                var groups = local_groups == null ? SafeTokenGroupsBuffer.Null 
                    : list.AddResource(SafeTokenGroupsBuffer.Create(local_groups));

                TOKEN_SOURCE tokenSource = new TOKEN_SOURCE("NT.NET");
                SecurityNativeMethods.AllocateLocallyUniqueId(out tokenSource.SourceIdentifier);
                QUOTA_LIMITS quota_limits = new QUOTA_LIMITS();
                return SecurityNativeMethods.LsaLogonUser(hlsa.Result, new LsaString(origin_name),
                    type, auth_pkg, buffer, buffer.GetLength(), groups,
                    tokenSource, out SafeLsaReturnBufferHandle profile,
                    out int cbProfile, out Luid logon_id, out SafeKernelObjectHandle token_handle,
                    quota_limits, out NtStatus subStatus).CreateResult(throw_on_error, () =>
                    {
                        using (profile)
                        {
                            return NtToken.FromHandle(token_handle);
                        }
                    });
            }
        }
    }
}
