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
using NtApiDotNet.Win32.Security.Authentication.Kerberos;
using NtApiDotNet.Win32.Security.Authentication.Ntlm;
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
        private readonly bool _managed;

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

        private static Dictionary<string, AuthenticationPackage> GetManagedPackages()
        {
            return new Dictionary<string, AuthenticationPackage>(StringComparer.OrdinalIgnoreCase)
            {
                { NTLM_NAME, new NtlmManagedAuthenticationPackage() },
                { KERBEROS_NAME, new KerberosManagedAuthenticationPackage() },
            };
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
        }

        private protected virtual ICredentialHandle CreateManagedHandle(SecPkgCredFlags cred_use_flag, AuthenticationCredentials credentials)
        {
            throw new NotImplementedException();
        }

        private AuthenticationPackage(string name) 
            : this(name, 0, 0, 0, 0, null, true)
        {
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
            if (credentials?.Mananged ?? _managed)
            {
                if (!_managed_packages.Value.TryGetValue(Name, out AuthenticationPackage package))
                    throw new ArgumentException($"Unsupported authentication package {Name}");
                return package.CreateManagedHandle(cred_use_flag, credentials);
            }
            
            return CredentialHandle.Create(principal, Name, auth_id, cred_use_flag, credentials);
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
        #endregion
    }
}
