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

        private static SafeKernelObjectHandle OpenClipboardToken(TokenAccessRights desired_access)
        {
            if (!Win32NativeMethods.GetClipboardAccessToken(out SafeKernelObjectHandle handle, desired_access))
            {
                throw new NtException(NtStatus.STATUS_NO_TOKEN);
            }
            return handle;
        }

        /// <summary>
        /// Open the current clipboard token.
        /// </summary>
        /// <param name="desired_access"></param>
        /// <param name="throw_on_error"></param>
        /// <returns></returns>
        public static NtResult<NtToken> OpenClipboardToken(TokenAccessRights desired_access, bool throw_on_error)
        {
            if (Win32NativeMethods.GetClipboardAccessToken(out SafeKernelObjectHandle handle, desired_access))
            {
                return NtToken.FromHandle(handle).CreateResult();
            }
            
            return NtStatus.STATUS_NO_TOKEN.CreateResultFromError<NtToken>(throw_on_error);
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

        /// <summary>
        /// Derive a package sid from a name.
        /// </summary>
        /// <param name="name">The name of the package.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The derived Sid</returns>
        public static NtResult<Sid> DerivePackageSidFromName(string name, bool throw_on_error)
        {
            int hr = Win32NativeMethods.DeriveAppContainerSidFromAppContainerName(name, out SafeSidBufferHandle sid);
            if (hr == 0)
            {
                using (sid)
                {
                    return new Sid(sid).CreateResult();
                }
            }

            return ((NtStatus)hr).CreateResultFromError<Sid>(throw_on_error);
        }

        /// <summary>
        /// Derive a package sid from a name.
        /// </summary>
        /// <param name="name">The name of the package.</param>
        /// <returns>The derived Sid</returns>
        public static Sid DerivePackageSidFromName(string name)
        {
            int hr = Win32NativeMethods.DeriveAppContainerSidFromAppContainerName(name, out SafeSidBufferHandle sid);
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
                int hr = Win32NativeMethods.DeriveRestrictedAppContainerSidFromAppContainerSidAndRestrictedName(sid_buf, restricted_name, out SafeSidBufferHandle sid);
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
                return DerivePackageSidFromName(name);
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
            if (!Win32NativeMethods.SaferCreateLevel(SaferScope.User, level, Win32NativeMethods.SAFER_LEVEL_OPEN, out IntPtr level_handle, IntPtr.Zero))
            {
                throw new SafeWin32Exception();
            }

            try
            {
                using (NtToken duptoken = token.Duplicate(TokenAccessRights.GenericRead | TokenAccessRights.GenericExecute))
                {
                    SafeKernelObjectHandle handle;
                    if (Win32NativeMethods.SaferComputeTokenFromLevel(level_handle, 
                        duptoken.Handle, out handle, make_inert ? SaferFlags.MakeInert : 0, IntPtr.Zero))
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
                Win32NativeMethods.SaferCloseLevel(level_handle);
            }
        }

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
                if (Win32NativeMethods.WTSEnumerateSessions(IntPtr.Zero, 0, 1, out pSessions, out dwSessionCount))
                {
                    IntPtr current = pSessions;
                    for (int i = 0; i < dwSessionCount; ++i)
                    {
                        WTS_SESSION_INFO session_info = (WTS_SESSION_INFO)Marshal.PtrToStructure(current, typeof(WTS_SESSION_INFO));

                        if (session_info.State == WTS_CONNECTSTATE_CLASS.WTSActive && Win32NativeMethods.WTSQueryUserToken(session_info.SessionId, out SafeKernelObjectHandle handle))
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
                    Win32NativeMethods.WTSFreeMemory(pSessions);
                }
            }

            return tokens;
        }
    }
}
