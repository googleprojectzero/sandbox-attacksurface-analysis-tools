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

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// Enumeration for safer level.
    /// </summary>
    public enum SaferLevel : uint
    {
        /// <summary>
        /// Constrained.
        /// </summary>
        Constrained = 0x10000,
        /// <summary>
        /// Fully trusted.
        /// </summary>
		FullyTrusted = 0x40000,
        /// <summary>
        /// Normal user.
        /// </summary>
		NormalUser = 0x20000,
        /// <summary>
        /// Untrusted.
        /// </summary>
		Untrusted = 0x01000,
	}

    /// <summary>
    /// Class to access tokens through various mechanisms.
    /// </summary>
    public static class TokenUtils
    {
        /// <summary>
        /// Logon a user using S4U
        /// </summary>
        /// <param name="user">The username.</param>
        /// <param name="realm">The user's realm.</param>
        /// <param name="logon_type"></param>
        /// <returns>The logged on token.</returns>
        public static NtToken GetLogonS4UToken(string user, string realm, SecurityLogonType logon_type)
        {
            switch (logon_type)
            {
                case SecurityLogonType.Batch:
                case SecurityLogonType.Interactive:
                case SecurityLogonType.Network:
                    break;
                default:
                    throw new ArgumentException("Invalid logon type for S4U");
            }

            return LogonUtils.LogonS4U(user, realm, logon_type);
        }

        /// <summary>
        /// Get the anonymous token.
        /// </summary>
        /// <param name="desired_access">The access rights for the opened token.</param>
        /// <returns>The anonymous token.</returns>
        public static NtToken GetAnonymousToken(TokenAccessRights desired_access)
        {
            using (var imp = NtThread.Current.ImpersonateAnonymousToken())
            {
                return NtToken.OpenThreadToken(NtThread.Current, true, false, desired_access);
            }
        }

        /// <summary>
        /// Get the anonymous token.
        /// </summary>
        /// <returns>The anonymous token.</returns>
        public static NtToken GetAnonymousToken()
        {
            return GetAnonymousToken(TokenAccessRights.MaximumAllowed);
        }

        /// <summary>
        /// Logon a user.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="domain">The user's domain.</param>
        /// <param name="password">The user's password.</param>
        /// <param name="logon_type">The logon token's type.</param>
        /// <param name="groups">Optional list of additonal groups to add.</param>
        /// <returns>The logged on token.</returns>
        public static NtToken GetLogonUserToken(string username, string domain, string password, SecurityLogonType logon_type, IEnumerable<UserGroup> groups)
        {
            switch (logon_type)
            {
                case SecurityLogonType.Batch:
                case SecurityLogonType.Interactive:
                case SecurityLogonType.Network:
                case SecurityLogonType.NetworkCleartext:
                case SecurityLogonType.NewCredentials:
                case SecurityLogonType.Service:
                    break;
                default:
                    throw new ArgumentException("Invalid logon type for Logon");
            }

            if (groups != null)
            {
                return LogonUtils.Logon(username, domain, password, logon_type, groups);
            }
            else
            {
                return LogonUtils.Logon(username, domain, password, logon_type);
            }
        }

        [DllImport("user32.dll", SetLastError=true)]
        private static extern bool GetClipboardAccessToken(out SafeKernelObjectHandle handle, TokenAccessRights desired_access);

        private static SafeKernelObjectHandle OpenClipboardToken(TokenAccessRights desired_access)
        {
            SafeKernelObjectHandle handle;
            if (!GetClipboardAccessToken(out handle, desired_access
                ))
            {
                throw new NtException(NtStatus.STATUS_NO_TOKEN);
            }
            return handle;
        }

        /// <summary>
        /// Get the token from the clipboard.
        /// </summary>
        /// <param name="desired_access">The access rights for the opened token.</param>
        /// <returns>The clipboard token.</returns>
        public static NtToken GetTokenFromClipboard(TokenAccessRights desired_access)
        {
            try
            {
                return NtToken.FromHandle(OpenClipboardToken(desired_access));
            }
            catch (NtException)
            {
                throw;
            }
            catch
            {
                throw new InvalidOperationException("GetClipboardAccessToken doesn't exist");
            }
        }

        /// <summary>
        /// Get the token from the clipboard.
        /// </summary>
        /// <returns>The clipboard token.</returns>
        public static NtToken GetTokenFromClipboard()
        {
            return GetTokenFromClipboard(TokenAccessRights.MaximumAllowed | TokenAccessRights.Query | TokenAccessRights.QuerySource
                | TokenAccessRights.ReadControl);
        }

        const int SAFER_LEVEL_OPEN = 1;

        [Flags]
        enum SaferScope
        {
            Machine = 1,
            User = 2
        }

        [Flags]
        enum SaferFlags
        {
            NullIfEqual = 1,
            CompareOnly = 2,
            MakeInert = 4,
            WantFlags = 8,
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool SaferCreateLevel(SaferScope dwScopeId, SaferLevel dwLevelId, int OpenFlags, out IntPtr pLevelHandle, IntPtr lpReserved);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool SaferCloseLevel(IntPtr hLevelHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool SaferComputeTokenFromLevel(IntPtr LevelHandle, SafeHandle InAccessToken, 
            out SafeKernelObjectHandle OutAccessToken, SaferFlags dwFlags, IntPtr lpReserved);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern IntPtr FreeSid(IntPtr sid);

        [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
        static extern int DeriveAppContainerSidFromAppContainerName(
            string pszAppContainerName,
            out SafeSidBufferHandle ppsidAppContainerSid
        );

        [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
        static extern int DeriveRestrictedAppContainerSidFromAppContainerSidAndRestrictedName(
            SafeSidBufferHandle psidAppContainerSid,
            string pszRestrictedAppContainerName,
            out SafeSidBufferHandle ppsidRestrictedAppContainerSid
        );

        /// <summary>
        /// Derive a package sid from a name.
        /// </summary>
        /// <param name="name">The name of the package.</param>
        /// <returns>The derived Sid</returns>
        public static Sid DerivePackageSidFromName(string name)
        {
            SafeSidBufferHandle sid;
            int hr = DeriveAppContainerSidFromAppContainerName(name, out sid);
            if (hr != 0)
            {
                Marshal.ThrowExceptionForHR(hr);
            }

            using (sid)
            {
                return new Sid(sid);
            }
        }

        /// <summary>
        /// Derive a restricted package sid from an existing pacakge sid.
        /// </summary>
        /// <param name="package_sid">The base package sid.</param>
        /// <param name="restricted_name">The restricted name for the sid.</param>
        /// <returns>The derived Sid.</returns>
        public static Sid DeriveRestrictedPackageSidFromSid(Sid package_sid, string restricted_name)
        {
            using (var sid_buf = package_sid.ToSafeBuffer())
            {
                SafeSidBufferHandle sid;
                int hr = DeriveRestrictedAppContainerSidFromAppContainerSidAndRestrictedName(sid_buf, restricted_name, out sid);                
                if (hr != 0)
                {
                    Marshal.ThrowExceptionForHR(hr);
                }

                using (sid)
                {
                    return new Sid(sid);
                }
            }
        }

        /// <summary>
        /// Derive a restricted package sid from an existing pacakge sid.
        /// </summary>
        /// <param name="base_name">The base package name.</param>
        /// <param name="restricted_name">The restricted name for the sid.</param>
        /// <returns>The derived Sid.</returns>
        public static Sid DeriveRestrictedPackageSidFromName(string base_name, string restricted_name)
        {
            return DeriveRestrictedPackageSidFromSid(DerivePackageSidFromName(base_name), restricted_name);
        }

        /// <summary>
        /// Get the package sid from a name.
        /// </summary>
        /// <param name="name">The name of the package, can be either an SDDL sid or a package name.</param>
        /// <returns>The derived sid.</returns>
        public static Sid GetPackageSidFromName(string name)
        {
            string package_sid_str = name;
            if (package_sid_str.StartsWith("S-1-"))
            {
                return new Sid(package_sid_str);
            }
            else
            {
                return TokenUtils.DerivePackageSidFromName(name);
            }
        }

        /// <summary>
        /// Get a safer token.
        /// </summary>
        /// <param name="token">The base token.</param>
        /// <param name="level">The safer level to use.</param>
        /// <param name="make_inert">True to make the token inert.</param>
        /// <returns>The safer token.</returns>
        public static NtToken GetTokenFromSaferLevel(NtToken token, SaferLevel level, bool make_inert)
        {
            IntPtr level_handle;

            if (!SaferCreateLevel(SaferScope.User, level, SAFER_LEVEL_OPEN, out level_handle, IntPtr.Zero))
            {
                throw new SafeWin32Exception();
            }

            try
            {
                using (NtToken duptoken = token.Duplicate(TokenAccessRights.GenericRead | TokenAccessRights.GenericExecute))
                {
                    SafeKernelObjectHandle handle;
                    if (SaferComputeTokenFromLevel(level_handle, duptoken.Handle, out handle, make_inert ? SaferFlags.MakeInert : 0, IntPtr.Zero))
                    {
                        return NtToken.FromHandle(handle);
                    }
                    else
                    {
                        throw new SafeWin32Exception();
                    }
                }
            }
            finally
            {
                SaferCloseLevel(level_handle);
            }
        }

        enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,              // User logged on to WinStation
            WTSConnected,           // WinStation connected to client
            WTSConnectQuery,        // In the process of connecting to client
            WTSShadow,              // Shadowing another WinStation
            WTSDisconnected,        // WinStation logged on without client
            WTSIdle,                // Waiting for client to connect
            WTSListen,              // WinStation is listening for connection
            WTSReset,               // WinStation is being reset
            WTSDown,                // WinStation is down due to error
            WTSInit,                // WinStation in initialization
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WTS_SESSION_INFO
        {
            public int SessionId;
            public IntPtr pWinStationName;
            public WTS_CONNECTSTATE_CLASS State;
        }

        [DllImport("wtsapi32.dll", SetLastError = true)]
        static extern bool WTSEnumerateSessions(
                IntPtr hServer,
                int Reserved,
                int Version,
                out IntPtr ppSessionInfo,
                out int pCount);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        static extern bool WTSQueryUserToken(int SessionId, out SafeKernelObjectHandle phToken);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        static extern void WTSFreeMemory(IntPtr memory);

        /// <summary>
        /// Get tokens for all logged on sessions.
        /// </summary>
        /// <remarks>Needs SeTcbPrivilege to work.</remarks>
        /// <returns>The list of session tokens.</returns>
        public static IEnumerable<NtToken> GetSessionTokens()
	    {
            List<NtToken> tokens = new List<NtToken>();
            IntPtr pSessions = IntPtr.Zero;
            int dwSessionCount = 0;
            try
            {
                if (WTSEnumerateSessions(IntPtr.Zero, 0, 1, out pSessions, out dwSessionCount))
                {
                    IntPtr current = pSessions;
                    for (int i = 0; i < dwSessionCount; ++i)
                    {
                        WTS_SESSION_INFO session_info = (WTS_SESSION_INFO)Marshal.PtrToStructure(current, typeof(WTS_SESSION_INFO));

                        if (session_info.State == WTS_CONNECTSTATE_CLASS.WTSActive && WTSQueryUserToken(session_info.SessionId, out SafeKernelObjectHandle handle))
                        {
                            tokens.Add(NtToken.FromHandle(handle));
                        }
                        current += Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                    }
                }
            }
            finally
            {
                if (pSessions != IntPtr.Zero)
                {
                    WTSFreeMemory(pSessions);
                }
            }

            return tokens;
        }
    }
}
