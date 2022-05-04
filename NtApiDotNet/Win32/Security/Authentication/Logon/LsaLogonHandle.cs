//  Copyright 2021 Google Inc. All Rights Reserved.
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
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authentication.Logon
{
    /// <summary>
    /// Class to represent an LSA logon handle.
    /// </summary>
    public sealed class LsaLogonHandle : IDisposable
    {
        private readonly SafeLsaLogonHandle _handle;

        private LsaLogonHandle(SafeLsaLogonHandle handle)
        {
            _handle = handle;
        }

        /// <summary>
        /// Connect to the LSA untrusted.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The LSA logon handle.</returns>
        public static NtResult<LsaLogonHandle> ConnectUntrusted(bool throw_on_error)
        {
            return SafeLsaLogonHandle.ConnectUntrusted(throw_on_error).Map(h => new LsaLogonHandle(h));
        }

        /// <summary>
        /// Connect to the LSA untrusted.
        /// </summary>
        /// <returns>The LSA logon handle.</returns>
        public static LsaLogonHandle ConnectUntrusted()
        {
            return ConnectUntrusted(true).Result;
        }

        /// <summary>
        /// Connect to LSA and register as a logon process.
        /// </summary>
        /// <param name="process_name">The arbitrary name of the process.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The LSA logon handle.</returns>
        public static NtResult<LsaLogonHandle> RegisterLogonProcess(string process_name, bool throw_on_error)
        {
            return SafeLsaLogonHandle.RegisterLogonProcess(process_name, throw_on_error).Map(h => new LsaLogonHandle(h));
        }

        /// <summary>
        /// Connect to LSA and register as a logon process.
        /// </summary>
        /// <param name="process_name">The arbitrary name of the process.</param>
        /// <returns>The LSA logon handle.</returns>
        public static LsaLogonHandle RegisterLogonProcess(string process_name)
        {
            return RegisterLogonProcess(process_name, true).Result;
        }

        /// <summary>
        /// Connect to LSA and register as a logon process, falling back to an untrusted connection.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The LSA logon handle.</returns>
        public static NtResult<LsaLogonHandle> Connect(bool throw_on_error)
        {
            return SafeLsaLogonHandle.Connect(throw_on_error).Map(h => new LsaLogonHandle(h));
        }

        /// <summary>
        /// Connect to LSA and register as a logon process, falling back to an untrusted connection.
        /// </summary>
        /// <returns>The LSA logon handle.</returns>
        public static LsaLogonHandle Connect()
        {
            return Connect(true).Result;
        }

        /// <summary>
        /// Logon a user.
        /// </summary>
        /// <param name="type">The type of logon.</param>
        /// <param name="auth_package">The authentication package to use.</param>
        /// <param name="origin_name">The name of the origin.</param>
        /// <param name="source_context">The token source context.</param>
        /// <param name="credentials">The authentication .</param>
        /// <param name="local_groups">Additional local groups.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The LSA logon result.</returns>
        public NtResult<LsaLogonResult> LsaLogonUser(SecurityLogonType type, uint auth_package, string origin_name,
            TokenSource source_context, ILsaLogonCredentials credentials, IEnumerable<UserGroup> local_groups, bool throw_on_error)
        {
            using (var list = new DisposableList())
            {
                var groups = local_groups == null ? SafeTokenGroupsBuffer.Null
                    : list.AddResource(SafeTokenGroupsBuffer.Create(local_groups));
                var buffer = list.AddResource(credentials.ToBuffer(list));

                QUOTA_LIMITS quota_limits = new QUOTA_LIMITS();
                return SecurityNativeMethods.LsaLogonUser(_handle, new LsaString(origin_name),
                    type, auth_package, buffer, buffer.GetLength(), groups,
                    source_context, out SafeLsaReturnBufferHandle profile,
                    out int cbProfile, out Luid logon_id, out SafeKernelObjectHandle token_handle,
                    quota_limits, out NtStatus subStatus).CreateResult(throw_on_error, () =>
                    {
                        profile.InitializeLength(cbProfile);
                        return new LsaLogonResult(NtToken.FromHandle(token_handle), profile, logon_id, quota_limits);
                    });
            }
        }

        /// <summary>
        /// Logon a user.
        /// </summary>
        /// <param name="type">The type of logon.</param>
        /// <param name="auth_package">The authentication package to use.</param>
        /// <param name="origin_name">The name of the origin.</param>
        /// <param name="source_context">The token source context.</param>
        /// <param name="credentials">The authentication credentials.</param>
        /// <param name="local_groups">Additional local groups.</param>
        /// <returns>The LSA logon result.</returns>
        public LsaLogonResult LsaLogonUser(SecurityLogonType type, uint auth_package, string origin_name,
            TokenSource source_context, ILsaLogonCredentials credentials, IEnumerable<UserGroup> local_groups)
        {
            return LsaLogonUser(type, auth_package, origin_name, source_context, credentials, local_groups, true).Result;
        }

        /// <summary>
        /// Logon a user.
        /// </summary>
        /// <param name="type">The type of logon.</param>
        /// <param name="auth_package">The authentication package to use.</param>
        /// <param name="origin_name">The name of the origin.</param>
        /// <param name="source_context">The token source context.</param>
        /// <param name="credentials">The authentication credentials.</param>
        /// <param name="local_groups">Additional local groups.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The LSA logon result.</returns>
        public NtResult<LsaLogonResult> LsaLogonUser(SecurityLogonType type, string auth_package, string origin_name,
            TokenSource source_context, ILsaLogonCredentials credentials, IEnumerable<UserGroup> local_groups, bool throw_on_error)
        {
            var auth_pkg = _handle.LookupAuthPackage(auth_package, throw_on_error);
            if (!auth_pkg.IsSuccess)
                return auth_pkg.Cast<LsaLogonResult>();
            return LsaLogonUser(type, auth_pkg.Result, origin_name, source_context, credentials, local_groups, throw_on_error);
        }

        /// <summary>
        /// Logon a user.
        /// </summary>
        /// <param name="type">The type of logon.</param>
        /// <param name="auth_package">The authentication package to use.</param>
        /// <param name="origin_name">The name of the origin.</param>
        /// <param name="source_context">The token source context.</param>
        /// <param name="credentials">The authentication credentials.</param>
        /// <param name="local_groups">Additional local groups.</param>
        /// <returns>The LSA logon result.</returns>
        public LsaLogonResult LsaLogonUser(SecurityLogonType type, string auth_package, string origin_name,
            TokenSource source_context, ILsaLogonCredentials credentials, IEnumerable<UserGroup> local_groups)
        {
            return LsaLogonUser(type, auth_package, origin_name, source_context, credentials, local_groups, true).Result;
        }

        /// <summary>
        /// Logon a user.
        /// </summary>
        /// <param name="type">The type of logon.</param>
        /// <param name="auth_package">The authentication package to use.</param>
        /// <param name="credentials">The authentication credentials.</param>
        /// <returns>The LSA logon result.</returns>
        public LsaLogonResult LsaLogonUser(SecurityLogonType type, string auth_package, ILsaLogonCredentials credentials)
        {
            return LsaLogonUser(type, auth_package, "TEMP", new TokenSource("NT.NET"), credentials, null);
        }

        /// <summary>
        /// Lookup the ID of an authentication package.
        /// </summary>
        /// <param name="auth_package">The authentication package to use.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The authentication package ID.</returns>
        public NtResult<uint> LsaLookupAuthenticationPackage(string auth_package, bool throw_on_error)
        {
            return _handle.LookupAuthPackage(auth_package, throw_on_error);
        }

        /// <summary>
        /// Lookup the ID of an authentication package.
        /// </summary>
        /// <param name="auth_package">The authentication package to use.</param>
        /// <returns>The authentication package ID.</returns>
        public uint LsaLookupAuthenticationPackage(string auth_package)
        {
            return LsaLookupAuthenticationPackage(auth_package, true).Result;
        }

        /// <summary>
        /// Call an authentication package.
        /// </summary>
        /// <param name="auth_package">The authentication package to call.</param>
        /// <param name="buffer">The buffer to pass to the authentication package.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the call.</returns>
        public NtResult<LsaCallPackageResult> LsaCallAuthenticationPackage(uint auth_package, SafeBuffer buffer, bool throw_on_error)
        {
            return _handle.CallPackage(auth_package, buffer, throw_on_error).Map(r => new LsaCallPackageResult(r));
        }

        /// <summary>
        /// Call an authentication package.
        /// </summary>
        /// <param name="auth_package">The authentication package to call.</param>
        /// <param name="buffer">The buffer to pass to the authentication package.</param>
        /// <returns>The result of the call.</returns>
        public LsaCallPackageResult LsaCallAuthenticationPackage(uint auth_package, SafeBuffer buffer)
        {
            return LsaCallAuthenticationPackage(auth_package, buffer, true).Result;
        }

        /// <summary>
        /// Call an authentication package.
        /// </summary>
        /// <param name="auth_package">The authentication package to call.</param>
        /// <param name="buffer">The buffer to pass to the authentication package.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The result of the call.</returns>
        public NtResult<LsaCallPackageResult> LsaCallAuthenticationPackage(string auth_package, SafeBuffer buffer, bool throw_on_error)
        {
            var auth_pkg = _handle.LookupAuthPackage(auth_package, throw_on_error);
            if (!auth_pkg.IsSuccess)
                return auth_pkg.Cast<LsaCallPackageResult>();
            return LsaCallAuthenticationPackage(auth_pkg.Result, buffer, throw_on_error);
        }

        /// <summary>
        /// Call an authentication package.
        /// </summary>
        /// <param name="auth_package">The authentication package to call.</param>
        /// <param name="buffer">The buffer to pass to the authentication package.</param>
        /// <returns>The result of the call.</returns>
        public LsaCallPackageResult LsaCallAuthenticationPackage(string auth_package, SafeBuffer buffer)
        {
            return LsaCallAuthenticationPackage(auth_package, buffer, true).Result;
        }

        /// <summary>
        /// Dispose of the LSA logon handle.
        /// </summary>
        public void Dispose()
        {
            ((IDisposable)_handle).Dispose();
        }
    }
}
