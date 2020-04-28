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

using NtApiDotNet.Win32.SafeHandles;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// Class to represent a Local Logon Session.
    /// </summary>
    public sealed class LogonSession
    {
        /// <summary>
        /// Logon/Authentication ID for session.
        /// </summary>
        public Luid LogonId { get; }
        /// <summary>
        /// Username.
        /// </summary>
        public string UserName { get; }
        /// <summary>
        /// Logon domain.
        /// </summary>
        public string LogonDomain { get; }
        /// <summary>
        /// Get the FQ User Name.
        /// </summary>
        public string FullQualifiedUserName
        {
            get
            {
                if (Sid != null)
                {
                    var name = NtSecurity.LookupAccountSid(Sid, false);
                    if (name.IsSuccess)
                        return name.Result;
                }

                if (string.IsNullOrEmpty(LogonDomain))
                {
                    return UserName;
                }
                return $"{LogonDomain}\\{UserName}";
            }
        }
        /// <summary>
        /// Authentication package.
        /// </summary>
        public string AuthenticationPackage { get; }
        /// <summary>
        /// Logon type.
        /// </summary>
        public SecurityLogonType LogonType { get; }
        /// <summary>
        /// Session ID.
        /// </summary>
        public int SessionId { get; }
        /// <summary>
        /// User SID.
        /// </summary>
        public Sid Sid { get; }
        /// <summary>
        /// Logon Time.
        /// </summary>
        public DateTime LogonTime { get; }
        /// <summary>
        /// Logon Server.
        /// </summary>
        public string LogonServer { get; }
        /// <summary>
        /// DNS Domain Name.
        /// </summary>
        public string DnsDomainName { get; }
        /// <summary>
        /// User Principal Name.
        /// </summary>
        public string Upn { get; }
        /// <summary>
        /// User Flags.
        /// </summary>
        public LsaLogonUserFlags UserFlags { get; }
        /// <summary>
        /// Last successful logon.
        /// </summary>
        public DateTime LastSuccessfulLogon { get; }
        /// <summary>
        /// Last failed logon.
        /// </summary>
        public DateTime LastFailedLogon { get; }
        /// <summary>
        /// Count of failed logon attempts.
        /// </summary>
        public int FailedAttemptCountSinceLastSuccessfulLogon { get; }
        /// <summary>
        /// Logon script path.
        /// </summary>
        public string LogonScript { get; }
        /// <summary>
        /// Profile path.
        /// </summary>
        public string ProfilePath { get; }
        /// <summary>
        /// Home directory.
        /// </summary>
        public string HomeDirectory { get; }
        /// <summary>
        /// Home directory drive.
        /// </summary>
        public string HomeDirectoryDrive { get; }
        /// <summary>
        /// Logoff time.
        /// </summary>
        public DateTime LogoffTime { get; }
        /// <summary>
        /// Kickoff Time.
        /// </summary>
        public DateTime KickOffTime { get; }
        /// <summary>
        /// Time password last set.
        /// </summary>
        public DateTime PasswordLastSet { get; }
        /// <summary>
        /// Password can change.
        /// </summary>
        public DateTime PasswordCanChange { get; }
        /// <summary>
        /// Password must change.
        /// </summary>
        public DateTime PasswordMustChange { get; }

        private LogonSession(in SECURITY_LOGON_SESSION_DATA session_data)
        {
            LogonId = session_data.LogonId;
            UserName = session_data.UserName.ToString();
            LogonDomain = session_data.LogonDomain.ToString();
            AuthenticationPackage = session_data.AuthenticationPackage.ToString();
            LogonType = session_data.LogonType;
            SessionId = session_data.Session;
            Sid = session_data.Sid != IntPtr.Zero ? new Sid(session_data.Sid) : null;
            LogonTime = session_data.LogonTime.ToDateTime();
            LogonServer = session_data.LogonServer.ToString();
            DnsDomainName = session_data.DnsDomainName.ToString();
            Upn = session_data.Upn.ToString();
            UserFlags = session_data.UserFlags;
            LastSuccessfulLogon = session_data.LastLogonInfo.LastSuccessfulLogon.ToDateTime();
            LastFailedLogon = session_data.LastLogonInfo.LastFailedLogon.ToDateTime();
            FailedAttemptCountSinceLastSuccessfulLogon = session_data.LastLogonInfo.FailedAttemptCountSinceLastSuccessfulLogon;
            LogonScript = session_data.LogonScript.ToString();
            ProfilePath = session_data.ProfilePath.ToString();
            HomeDirectory = session_data.HomeDirectory.ToString();
            HomeDirectoryDrive = session_data.HomeDirectoryDrive.ToString();
            LogoffTime = session_data.LogoffTime.ToDateTime();
            KickOffTime = session_data.KickOffTime.ToDateTime();
            PasswordLastSet = session_data.PasswordLastSet.ToDateTime();
            PasswordCanChange = session_data.PasswordCanChange.ToDateTime();
            PasswordMustChange = session_data.PasswordMustChange.ToDateTime();
        }

        /// <summary>
        /// Get a logon session.
        /// </summary>
        /// <param name="luid">The logon session ID.</param>
        /// <param name="throw_on_error">True to thrown on error.</param>
        /// <returns>The logon session.</returns>
        internal static NtResult<LogonSession> GetLogonSession(Luid luid, bool throw_on_error)
        {
            return SecurityNativeMethods.LsaGetLogonSessionData(ref luid, out SafeLsaReturnBufferHandle buffer).CreateResult(throw_on_error,
                () => {
                    using (buffer)
                    {
                        buffer.Initialize<SECURITY_LOGON_SESSION_DATA>(1);
                        var value = buffer.Read<SECURITY_LOGON_SESSION_DATA>(0);
                        return new LogonSession(value);
                    }
                });
        }

        /// <summary>
        /// Get the logon session LUIDs
        /// </summary>
        /// <param name="throw_on_error">True throw on error.</param>
        /// <returns>The list of logon sessions. Only returns ones you can access.</returns>
        internal static NtResult<IEnumerable<Luid>> GetLogonSessionIds(bool throw_on_error)
        {
            return SecurityNativeMethods.LsaEnumerateLogonSessions(out int count, out SafeLsaReturnBufferHandle buffer).CreateResult(throw_on_error,
                () => {
                    using (buffer)
                    {
                        buffer.Initialize<Luid>((uint)count);
                        Luid[] luids = new Luid[count];
                        buffer.ReadArray(0, luids, 0, count);
                        return (IEnumerable<Luid>)luids;
                    }
                });
        }

        /// <summary>
        /// Get the logon sessions.
        /// </summary>
        /// <param name="throw_on_error">True throw on error.</param>
        /// <returns>The list of logon sessions. Only returns ones you can access.</returns>
        internal static NtResult<IEnumerable<LogonSession>> GetLogonSessions(bool throw_on_error)
        {
            var luids = GetLogonSessionIds(throw_on_error);
            if (!luids.IsSuccess)
                return luids.Cast<IEnumerable<LogonSession>>();
            var sessions = luids.Result.Select(l => GetLogonSession(l, false)).Where(r => r.IsSuccess).ToArray();
            return sessions.Select(r => r.Result).CreateResult();
        }
    }
}
