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

using NtApiDotNet.Win32.Rpc;
using NtApiDotNet.Win32.SafeHandles;
using NtApiDotNet.Win32.Security.Native;
using System;

namespace NtApiDotNet.Win32.Security.Authorization
{
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
        #region Public Properties
        /// <summary>
        /// The name of the resource manager if any.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// Indicates if this resource manager is connected to a remote access server.
        /// </summary>
        public bool Remote { get; }
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
            return AuthZContext.Create(_handle, token, Remote, throw_on_error);
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

        /// <summary>
        /// Create a client context from a Token.
        /// </summary>
        /// <param name="sid">The sid to create the context from.</param>
        /// <param name="flags">Flags for intialization.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The created client context.</returns>
        public NtResult<AuthZContext> CreateContext(Sid sid, AuthZContextInitializeSidFlags flags, bool throw_on_error)
        {
            return AuthZContext.Create(_handle, flags, sid, Remote, throw_on_error);
        }

        /// <summary>
        /// Create a client context from a Token.
        /// </summary>
        /// <param name="sid">The sid to create the context from.</param>
        /// <param name="flags">Flags for intialization.</param>
        /// <returns>The created client context.</returns>
        public AuthZContext CreateContext(Sid sid, AuthZContextInitializeSidFlags flags)
        {
            return CreateContext(sid, flags, true).Result;
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
            AuthZResourceManager ret = new AuthZResourceManager(name, false);
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

        /// <summary>
        /// Create a remote AuthZ resource manager from a raw binding string.
        /// </summary>
        /// <param name="string_binding">The RPC string binding for the server.</param>
        /// <param name="server_spn">The SPN for the server.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The created AuthZ resource manager.</returns>
        public static NtResult<AuthZResourceManager> Create(string string_binding, string server_spn, bool throw_on_error)
        {
            var binding = RpcStringBinding.Parse(string_binding);
            AUTHZ_RPC_INIT_INFO_CLIENT client_info = new AUTHZ_RPC_INIT_INFO_CLIENT
            {
                version = AUTHZ_RPC_INIT_INFO_CLIENT.AUTHZ_RPC_INIT_INFO_CLIENT_VERSION_V1,
                ProtSeq = binding.ProtocolSequence,
                Options = binding.NetworkOptions,
                NetworkAddr = binding.NetworkAddress,
                Endpoint = binding.Endpoint,
                ObjectUuid = binding.ObjUuid?.ToString() ?? string.Empty,
                ServerSpn = server_spn
            };
            return Create(client_info, throw_on_error);
        }

        /// <summary>
        /// Create a remote AuthZ resource manager from a raw binding string.
        /// </summary>
        /// <param name="string_binding">The RPC string binding for the server.</param>
        /// <param name="server_spn">The SPN for the server.</param>
        /// <returns>The created AuthZ resource manager.</returns>
        public static AuthZResourceManager Create(string string_binding, string server_spn)
        {
            return Create(string_binding, server_spn, true).Result;
        }

        /// <summary>
        /// Create a remote AuthZ resource manager from a raw binding string.
        /// </summary>
        /// <param name="server">The address of the server.</param>
        /// <param name="server_spn">The SPN for the server.</param>
        /// <param name="type">Specify the type of </param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The created AuthZ resource manager.</returns>
        public static NtResult<AuthZResourceManager> Create(string server, string server_spn, AuthZResourceManagerRemoteServiceType type, bool throw_on_error)
        {
            AUTHZ_RPC_INIT_INFO_CLIENT client_info = new AUTHZ_RPC_INIT_INFO_CLIENT
            {
                version = AUTHZ_RPC_INIT_INFO_CLIENT.AUTHZ_RPC_INIT_INFO_CLIENT_VERSION_V1,
                ProtSeq = RpcProtocolSequence.Tcp,
                Options = null,
                NetworkAddr = server,
                Endpoint = null,
                ObjectUuid = type == AuthZResourceManagerRemoteServiceType.Default ?
                    "5fc860e0-6f6e-4fc2-83cd-46324f25e90b" : "9a81c2bd-a525-471d-a4ed-49907c0b23da",
                ServerSpn = string.IsNullOrEmpty(server_spn) ? null : server_spn
            };
            return Create(client_info, throw_on_error);
        }

        /// <summary>
        /// Create a remote AuthZ resource manager from a raw binding string.
        /// </summary>
        /// <param name="server">The network address of the server.</param>
        /// <param name="server_spn">The SPN for the server.</param>
        /// <param name="type">Specify the type of </param>
        /// <returns>The created AuthZ resource manager.</returns>
        public static AuthZResourceManager Create(string server, string server_spn, AuthZResourceManagerRemoteServiceType type)
        {
            return Create(server, server_spn, type, true).Result;
        }

        #endregion

        #region Constructors
        private AuthZResourceManager(string name, bool remote)
        {
            Name = name ?? string.Empty;
            Remote = remote;
        }
        #endregion

        #region Private Members
        private SafeAuthZResourceManagerHandle _handle;
        private AuthZHandleCallbackAce _handle_callback_ace;

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

        private static NtResult<AuthZResourceManager> Create(in AUTHZ_RPC_INIT_INFO_CLIENT client_info, bool throw_on_error)
        {
            AuthZResourceManager ret = new AuthZResourceManager(client_info.NetworkAddr ?? string.Empty, true);
            return SecurityNativeMethods.AuthzInitializeRemoteResourceManager(client_info, 
                out ret._handle).CreateWin32Result(throw_on_error, () => ret);
        }

        #endregion
    }
}
