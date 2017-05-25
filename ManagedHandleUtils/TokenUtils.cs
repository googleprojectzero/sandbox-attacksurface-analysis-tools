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
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace SandboxAnalysisUtils
{
    public enum SaferLevel : uint
    {
        Constrained = 0x10000,
		FullyTrusted = 0x40000,
		NormalUser = 0x20000,
		Untrusted = 0x01000,
	}

    public static class TokenUtils
    {
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

        public static NtToken GetAnonymousToken(TokenAccessRights desired_access)
        {
            using (var imp = NtThread.Current.ImpersonateAnonymousToken())
            {
                return NtToken.OpenThreadToken(NtThread.Current, true, false, desired_access);
            }
        }

        public static NtToken GetAnonymousToken()
        {
            return GetAnonymousToken(TokenAccessRights.MaximumAllowed);
        }

        public static NtToken GetLogonUserToken(string username, string domain, string password, SecurityLogonType logon_type)
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

            return LogonUtils.Logon(username, domain, password, logon_type);
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
            out IntPtr ppsidAppContainerSid
        );

        public static Sid DerivePackageSidFromName(string name)
        {
            IntPtr sid = IntPtr.Zero;
            try
            {
                int hr = DeriveAppContainerSidFromAppContainerName(name, out sid);
                if (hr != 0)
                {
                    Marshal.ThrowExceptionForHR(hr);
                }

                return new Sid(sid);
            }
            finally
            {
                if (sid != IntPtr.Zero)
                {
                    FreeSid(sid);
                }
            }
        }

        public static Sid GetPackageSidFromName(string name)
        {
            string package_sid_str = name;
            if (package_sid_str.StartsWith("S-1-"))
            {
                return new Sid(package_sid_str);
            }
            else
            {
                return SandboxAnalysisUtils.TokenUtils.DerivePackageSidFromName(name);
            }
        }

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

        public static NtToken CreateProcessForToken(string cmdline, NtToken token, bool make_interactive)
        {
            using (NtToken newtoken = token.DuplicateToken(TokenType.Primary, SecurityImpersonationLevel.Anonymous, TokenAccessRights.MaximumAllowed))
            {
                string desktop = null;
                if (make_interactive)
                {
                    desktop = @"WinSta0\Default";
                    newtoken.SetSessionId(NtProcess.Current.SessionId);
                }

                using (Win32Process process = Win32Process.CreateProcessAsUser(newtoken, null, cmdline, CreateProcessFlags.None, desktop))
                {
                    return process.Process.OpenToken();
                }
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

                        SafeKernelObjectHandle handle;
                        if (session_info.State == WTS_CONNECTSTATE_CLASS.WTSActive && WTSQueryUserToken(session_info.SessionId, out handle))
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
