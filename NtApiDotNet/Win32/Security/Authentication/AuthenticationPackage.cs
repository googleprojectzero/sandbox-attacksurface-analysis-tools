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

using NtApiDotNet.Utilities.Memory;
using NtApiDotNet.Win32.SafeHandles;
using NtApiDotNet.Win32.Security.Authentication.Kerberos;
using NtApiDotNet.Win32.Security.Authentication.Negotiate;
using NtApiDotNet.Win32.Security.Authentication.Ntlm;
using NtApiDotNet.Win32.Security.Buffers;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// An authentication package entry.
    /// </summary>
    public class AuthenticationPackage
    {
        #region Private Members
        private static readonly Lazy<IReadOnlyList<AuthenticationPackage>> _native_packages = new Lazy<IReadOnlyList<AuthenticationPackage>>(GetNativePackages);
        private static readonly Lazy<Dictionary<string, AuthenticationPackage>> _managed_packages = new Lazy<Dictionary<string, AuthenticationPackage>>(GetManagedPackages);
        private static readonly Lazy<Dictionary<uint, AuthenticationPackage>> _native_packages_by_id = new Lazy<Dictionary<uint, AuthenticationPackage>>(GetNativePackageById);
        private readonly bool _managed;
        private readonly Lazy<uint> _package_id;

        private static IReadOnlyList<AuthenticationPackage> GetNativePackages()
        {
            List<AuthenticationPackage> packages = new List<AuthenticationPackage>();
            if (SecurityNativeMethods.EnumerateSecurityPackages(out int count,
            out IntPtr ppPackageInfo) == SecStatusCode.SUCCESS)
            {
                try
                {
                    packages.AddRange(ppPackageInfo.ReadArray<SecPkgInfo>(count).Select(p => new AuthenticationPackage(p)));
                }
                finally
                {
                    SecurityNativeMethods.FreeContextBuffer(ppPackageInfo);
                }
            }
            return packages.AsReadOnly();
        }

        private static Dictionary<uint, AuthenticationPackage> GetNativePackageById()
        {
            var ret = new Dictionary<uint, AuthenticationPackage>();
            using (var handle = SafeLsaLogonHandle.ConnectUntrusted(false))
            {
                if (!handle.IsSuccess)
                {
                    return ret;
                }

                foreach (var package in _native_packages.Value)
                {
                    var result = handle.Result.LookupAuthPackage(package.Name, false);
                    if (result.IsSuccess)
                    {
                        ret[result.Result] = package;
                    }
                }
            }
            return ret;
        }

        private static Dictionary<string, AuthenticationPackage> GetManagedPackages()
        {
            return new Dictionary<string, AuthenticationPackage>(StringComparer.OrdinalIgnoreCase)
            {
                { NTLM_NAME, new NtlmManagedAuthenticationPackage() },
                { KERBEROS_NAME, new KerberosManagedAuthenticationPackage() },
                { NEGOSSP_NAME, new NegotiateManagedAuthenticationPackage() },
            };
        }

        private uint GetPackageId()
        {
            using (var handle = SafeLsaLogonHandle.ConnectUntrusted(false))
            {
                if (handle.IsSuccess)
                {
                    var result = handle.Result.LookupAuthPackage(Name, false);
                    if (result.IsSuccess)
                    {
                        return result.Result;
                    }
                }
            }
            return uint.MaxValue;
        }

        private protected AuthenticationPackage(string name,
            SecPkgCapabilityFlag capabilities, int version,
            int rpc_id, int max_token_size, string comment,
            bool managed)
        {
            Name = name ?? throw new ArgumentNullException(nameof(name));
            Capabilities = capabilities;
            Version = version;
            RpcId = rpc_id;
            MaxTokenSize = max_token_size;
            Comment = comment ?? string.Empty;
            _managed = managed;
            if (managed)
            {
                _package_id = new Lazy<uint>(() => uint.MaxValue);
            }
            else
            {
                _package_id = new Lazy<uint>(GetPackageId);
            }
        }

        private protected virtual ICredentialHandle CreateManagedHandle(SecPkgCredFlags cred_use_flag, AuthenticationCredentials credentials)
        {
            throw new NotImplementedException();
        }
        #endregion

        #region Public Constants
        /// <summary>
        /// Authentication package name for MSV1.0
        /// </summary>
        public const string MSV1_0_NAME = "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0";

        /// <summary>
        /// Authentication package name for Kerberos.
        /// </summary>
        public const string KERBEROS_NAME = "Kerberos";

        /// <summary>
        /// Authentication package name for Negotiate.
        /// </summary>
        public const string NEGOSSP_NAME = "Negotiate";

        /// <summary>
        /// Authentication package name for NTLM.
        /// </summary>
        public const string NTLM_NAME = "NTLM";

        /// <summary>
        /// Authentication package name for Digest.
        /// </summary>
        public const string DIGEST_NAME = "WDigest";

        /// <summary>
        /// Authentication package name for SChannel.
        /// </summary>
        public const string SCHANNEL_NAME = "SChannel";

        /// <summary>
        /// Authentication package name for CredSSP.
        /// </summary>
        public const string CREDSSP_NAME = "CredSSP";

        /// <summary>
        /// Authentication package name for TSSSP.
        /// </summary>
        public const string TSSSP_NAME = "TSSSP";

        /// <summary>
        /// Authentication package name for pku2u.
        /// </summary>
        public const string PKU2U_NAME = "pku2u";

        /// <summary>
        /// All package ID.
        /// </summary>
        public const uint SECPKG_ALL_PACKAGES = unchecked((uint)-2);
        #endregion

        #region Public Properties
        /// <summary>
        /// Capabilities of the package.
        /// </summary>
        public SecPkgCapabilityFlag Capabilities { get; }
        /// <summary>
        /// Version of the package.
        /// </summary>
        public int Version { get; }
        /// <summary>
        /// RPC DCE ID.
        /// </summary>
        public int RpcId { get; }
        /// <summary>
        /// Max token size.
        /// </summary>
        public int MaxTokenSize { get; }
        /// <summary>
        /// Name of the package.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// Comment for the package.
        /// </summary>
        public string Comment { get; }
        /// <summary>
        /// Get the LSA assigned package ID.
        /// </summary>
        public uint PackageId => _package_id.Value;
        #endregion

        #region Internal Members
        internal AuthenticationPackage(SecPkgInfo pkg) 
            : this(pkg.Name, pkg.fCapabilities, pkg.wVersion, 
                  pkg.wRPCID, pkg.cbMaxToken, pkg.Comment, false)
        {
        }

        internal static bool CheckNtlm(string package_name)
        {
            return package_name.Equals(NTLM_NAME, StringComparison.OrdinalIgnoreCase);
        }

        internal static bool CheckKerberos(string package_name)
        {
            return package_name.Equals(KERBEROS_NAME, StringComparison.OrdinalIgnoreCase);
        }

        internal static bool CheckNegotiate(string package_name)
        {
            return package_name.Equals(NEGOSSP_NAME, StringComparison.OrdinalIgnoreCase);
        }

        internal static bool CheckDigest(string package_name)
        {
            return package_name.Equals(DIGEST_NAME, StringComparison.OrdinalIgnoreCase);
        }

        internal static bool CheckSChannel(string package_name)
        {
            return package_name.Equals(SCHANNEL_NAME, StringComparison.OrdinalIgnoreCase);
        }

        internal static bool CheckCredSSP(string package_name)
        {
            return package_name.Equals(CREDSSP_NAME, StringComparison.OrdinalIgnoreCase);
        }

        internal static bool CheckTSSSP(string package_name)
        {
            return package_name.Equals(TSSSP_NAME, StringComparison.OrdinalIgnoreCase);
        }

        internal static bool CheckPKU2U(string package_name)
        {
            return package_name.Equals(PKU2U_NAME, StringComparison.OrdinalIgnoreCase);
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Create a new credential handle.
        /// </summary>
        /// <param name="cred_use_flag">Credential user flags.</param>
        /// <param name="credentials">Optional credentials.</param>
        /// <param name="principal">User principal.</param>
        /// <param name="auth_id">Optional authentication ID for the user.</param>
        /// <returns>The credential handle.</returns>
        public ICredentialHandle CreateHandle(SecPkgCredFlags cred_use_flag, 
            AuthenticationCredentials credentials = null, string principal = null, Luid? auth_id = null)
        {
            // Check for the use of a managed credential handle.
            bool creds_managed = credentials?.Mananged ?? false;

            if (creds_managed || _managed)
            {
                if (!_managed_packages.Value.TryGetValue(Name, out AuthenticationPackage package))
                    throw new ArgumentException($"Unsupported authentication package {Name}");
                return package.CreateManagedHandle(cred_use_flag, credentials);
            }
            
            return CredentialHandle.Create(principal, Name, auth_id, cred_use_flag, credentials);
        }

        /// <summary>
        /// Create a client authentication context.
        /// </summary>
        /// <param name="credentials">Optional credentials.</param>
        /// <param name="req_attributes">Request attribute flags.</param>
        /// <param name="target">Target SPN (optional).</param>
        /// <param name="data_rep">Data representation.</param>
        /// <param name="channel_binding">Optional channel binding token.</param>
        /// <param name="initialize">Specify to default initialize the context. Must call Continue with an auth token to initialize.</param>
        /// <returns>The client authentication context.</returns>
        public IClientAuthenticationContext CreateClient(AuthenticationCredentials credentials = null,
            InitializeContextReqFlags req_attributes = InitializeContextReqFlags.None,
            string target = null, SecurityChannelBinding channel_binding = null, SecDataRep data_rep = SecDataRep.Native,
            bool initialize = true)
        {
            var handle = CreateHandle(SecPkgCredFlags.Outbound, credentials);
            try
            {
                return handle.CreateClient(req_attributes,
                    target, channel_binding, data_rep, initialize, true);
            }
            catch
            {
                handle?.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Create a server authentication context.
        /// </summary>
        /// <param name="credentials">Optional credentials.</param>
        /// <param name="req_attributes">Request attribute flags.</param>
        /// <param name="channel_binding">Optional channel binding token.</param>
        /// <param name="data_rep">Data representation.</param>
        /// <returns>The server authentication context.</returns>
        public IServerAuthenticationContext CreateServer(AuthenticationCredentials credentials = null,
            AcceptContextReqFlags req_attributes = AcceptContextReqFlags.None,
            SecurityChannelBinding channel_binding = null, SecDataRep data_rep = SecDataRep.Native)
        {
            var handle = CreateHandle(SecPkgCredFlags.Inbound, credentials);
            try
            {
                return handle.CreateServer(req_attributes, channel_binding, data_rep, true);
            }
            catch
            {
                handle?.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Change an account password using this package.
        /// </summary>
        /// <param name="domain">The user's domain name.</param>
        /// <param name="username">The user's name.</param>
        /// <param name="old_password">The user's old password.</param>
        /// <param name="new_password">The user's new password.</param>
        /// <param name="impersonating">Whether the caller is impersonating.</param>
        public void ChangeAccountPassword(string domain, string username,
          string old_password, string new_password, bool impersonating = false)
        {
            var change_pass_buffer = new SecurityBufferAllocMem(SecurityBufferType.ChangePassResponse);
            using (var desc = SecurityBufferDescriptor.Create(change_pass_buffer))
            {
                SecurityNativeMethods.ChangeAccountPassword(Name, domain, username,
                    old_password, new_password, impersonating, 0, desc.Value).CheckResult();
                desc.UpdateBuffers();
            }
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The name of the package.</returns>
        public override string ToString()
        {
            return Name;
        }
        #endregion

        #region Static Methods
        /// <summary>
        /// Get authentication packages.
        /// </summary>
        /// <returns>The list of authentication packages.</returns>
        public static IEnumerable<AuthenticationPackage> Get()
        {
            return NtObjectUtils.IsWindows ? _native_packages.Value : _managed_packages.Value.Values.AsEnumerable();
        }

        /// <summary>
        /// Get authentication package names.
        /// </summary>
        /// <returns>The list of authentication package names.</returns>
        public static IEnumerable<string> GetNames()
        {
            return Get().Select(p => p.Name);
        }

        /// <summary>
        /// Get an authentication package by name.
        /// </summary>
        /// <param name="package">The name of the package.</param>
        /// <param name="managed">Request a managed package.</param>
        /// <returns>The authentication package.</returns>
        public static AuthenticationPackage FromName(string package, bool managed)
        {
            if (NtObjectUtils.IsWindows && !managed)
            {
                SecurityNativeMethods.QuerySecurityPackageInfo(package, out IntPtr package_info).CheckResult();
                try
                {
                    return new AuthenticationPackage(package_info.ReadStruct<SecPkgInfo>());
                }
                finally
                {
                    SecurityNativeMethods.FreeContextBuffer(package_info);
                }
            }
            else
            {
                if (_managed_packages.Value.TryGetValue(package, out AuthenticationPackage ret))
                    return ret;
                throw new ArgumentException($"Unsupported authentication package {package}");
            }
        }

        /// <summary>
        /// Get an authentication package by name.
        /// </summary>
        /// <param name="package">The name of the package.</param>
        /// <returns>The authentication package.</returns>
        public static AuthenticationPackage FromName(string package)
        {
            return FromName(package, false);
        }

        /// <summary>
        /// Get the authentication package by it's package ID.
        /// </summary>
        /// <param name="package_id">The package ID.</param>
        /// <returns>The authentication package. Returns null if not found.</returns>
        /// <remarks>The package ID is epemeral and is subject to change.</remarks>
        public static AuthenticationPackage FromPackageId(uint package_id)
        {
            if (_native_packages_by_id.Value.TryGetValue(package_id, out AuthenticationPackage package))
                return package;
            return null;
        }

        /// <summary>
        /// Create a new credential handle.
        /// </summary>
        /// <param name="package">The name of the package.</param>
        /// <param name="cred_use_flag">Credential user flags.</param>
        /// <param name="credentials">Optional credentials.</param>
        /// <param name="principal">User principal.</param>
        /// <param name="auth_id">Optional authentication ID for the user.</param>
        /// <returns>The credential handle.</returns>
        public static ICredentialHandle CreateHandle(string package, SecPkgCredFlags cred_use_flag,
            AuthenticationCredentials credentials = null, string principal = null, Luid? auth_id = null)
        {
            return FromName(package).CreateHandle(cred_use_flag, credentials, principal, auth_id);
        }

        /// <summary>
        /// Create a client authentication context.
        /// </summary>
        /// <param name="package">The name of the package.</param>
        /// <param name="credentials">Optional credentials.</param>
        /// <param name="req_attributes">Request attribute flags.</param>
        /// <param name="target">Target SPN (optional).</param>
        /// <param name="data_rep">Data representation.</param>
        /// <param name="channel_binding">Optional channel binding token.</param>
        /// <param name="initialize">Specify to default initialize the context. Must call Continue with an auth token to initialize.</param>
        /// <returns>The client authentication context.</returns>
        public static IClientAuthenticationContext CreateClient(string package, AuthenticationCredentials credentials = null, 
            InitializeContextReqFlags req_attributes = InitializeContextReqFlags.None,
            string target = null, SecurityChannelBinding channel_binding = null, SecDataRep data_rep = SecDataRep.Native,
            bool initialize = true)
        {
            return FromName(package).CreateClient(credentials, req_attributes, target, channel_binding, data_rep, initialize);
        }

        /// <summary>
        /// Create a server authentication context.
        /// </summary>
        /// <param name="package">The name of the package.</param>
        /// <param name="credentials">Optional credentials.</param>
        /// <param name="req_attributes">Request attribute flags.</param>
        /// <param name="channel_binding">Optional channel binding token.</param>
        /// <param name="data_rep">Data representation.</param>
        /// <returns>The server authentication context.</returns>
        public static IServerAuthenticationContext CreateServer(string package, AuthenticationCredentials credentials = null,
            AcceptContextReqFlags req_attributes = AcceptContextReqFlags.None,
            SecurityChannelBinding channel_binding = null, SecDataRep data_rep = SecDataRep.Native)
        {
            return FromName(package).CreateServer(credentials, req_attributes, channel_binding, data_rep);
        }

        /// <summary>
        /// Conversion operator from a package name.
        /// </summary>
        /// <param name="package">The name of the package.</param>
        public static explicit operator AuthenticationPackage(string package) => FromName(package);
        #endregion
    }
}
