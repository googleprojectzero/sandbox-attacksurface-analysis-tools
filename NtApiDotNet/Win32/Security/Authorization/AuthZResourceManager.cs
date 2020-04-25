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

namespace NtApiDotNet.Win32.Security.Authorization
{
    /// <summary>
    /// Initialization flags for resource manager.
    /// </summary>
    [Flags]
    public enum AuthZResourceManagerInitializeFlags
    {
        /// <summary>
        /// None
        /// </summary>
        None = 0,
        /// <summary>
        /// Disable auditing.
        /// </summary>
        NoAudit = 1,
        /// <summary>
        /// Initialize using impersonation token.
        /// </summary>
        InitializeUnderImpersonation = 2,
        /// <summary>
        /// Disable central access policies.
        /// </summary>
        NoCentralAccessPolicies = 4
    }

    /// <summary>
    /// Delegate to handle a callback ACE.
    /// </summary>
    /// <param name="ace">The ACE to handle.</param>
    /// <returns>True if the ACE should be processed.</returns>
    public delegate bool AuthZHandleCallbackAce(Ace ace);

    /// <summary>
    /// Class to represent a AuthZ Resource Manager.
    /// </summary>
    public sealed class AuthZResourceManager : IDisposable
    {
        private SafeAuthZResourceManagerHandle _handle;
        private AuthZHandleCallbackAce _handle_callback_ace;

        #region Public Properties
        /// <summary>
        /// The name of the resource manager if any.
        /// </summary>
        public string Name { get; }
        #endregion

        #region Public Methods
        /// <summary>
        /// Dispose the resource manager.
        /// </summary>
        public void Dispose()
        {
            ((IDisposable)_handle).Dispose();
        }

        /// <summary>
        /// Create a client context from a Token.
        /// </summary>
        /// <param name="token">The token to create the context from.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The created client context.</returns>
        public NtResult<AuthZContext> CreateContext(NtToken token, bool throw_on_error)
        {
            return AuthZContext.Create(_handle, token, throw_on_error);
        }

        /// <summary>
        /// Create a client context from a Token.
        /// </summary>
        /// <param name="token">The token to create the context from.</param>
        /// <returns>The created client context.</returns>
        public AuthZContext CreateContext(NtToken token)
        {
            return CreateContext(token, true).Result;
        }

        #endregion

        #region Public Static Methods
        /// <summary>
        /// Create a new AuthZ resource manager.
        /// </summary>
        /// <param name="name">The name of the resource manager, optional.</param>
        /// <param name="flags">Optional flags for the resource manager.</param>
        /// <param name="handle_callback_ace">Optional callback to handle callback ACEs.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The created AuthZ resource manager.</returns>
        public static NtResult<AuthZResourceManager> Create(string name, AuthZResourceManagerInitializeFlags flags, AuthZHandleCallbackAce handle_callback_ace, bool throw_on_error)
        {
            AuthZResourceManager ret = new AuthZResourceManager(name);
            AuthzAccessCheckCallback callback = null;
            if (handle_callback_ace != null)
            {
                ret._handle_callback_ace = handle_callback_ace;
                callback = ret.HandleCallbackAce;
            }

            return SecurityNativeMethods.AuthzInitializeResourceManager(flags, callback, IntPtr.Zero,
                IntPtr.Zero, name, out ret._handle).CreateWin32Result(throw_on_error, () => ret);
        }

        /// <summary>
        /// Create a new AuthZ resource manager.
        /// </summary>
        /// <param name="name">The name of the resource manager, optional.</param>
        /// <param name="flags">Optional flags for the resource manager.</param>
        /// <param name="handle_callback_ace">Optional callback to handle callback ACEs.</param>
        /// <returns>The created AuthZ resource manager.</returns>
        public static AuthZResourceManager Create(string name, AuthZResourceManagerInitializeFlags flags, AuthZHandleCallbackAce handle_callback_ace)
        {
            return Create(name, flags, handle_callback_ace, true).Result;
        }

        /// <summary>
        /// Create a new AuthZ resource manager. Will not enable auditing.
        /// </summary>
        /// <returns>The created AuthZ resource manager.</returns>
        public static AuthZResourceManager Create()
        {
            return Create(null, AuthZResourceManagerInitializeFlags.NoAudit, null);
        }

        #endregion

        #region Constructors
        private AuthZResourceManager(string name)
        {
            Name = name ?? string.Empty;
        }
        #endregion

        #region Private Members
        private bool HandleCallbackAce(
            IntPtr hAuthzClientContext,
            IntPtr pAce,
            IntPtr pArgs,
            out bool pbAceApplicable)
        {
            pbAceApplicable = false;
            try
            {
                pbAceApplicable = _handle_callback_ace(Ace.Parse(pAce));
                return true;
            }
            catch
            {
                return false;
            }
        }
        #endregion
    }
}
