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

using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authentication
{
    /// <summary>
    /// An authentication package entry.
    /// </summary>
    public sealed class AuthenticationPackage
    {
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

        private AuthenticationPackage(SecPkgInfo pkg)
        {
            Capabilities = pkg.fCapabilities;
            Version = pkg.wVersion;
            RpcId = pkg.wRPCID;
            MaxTokenSize = pkg.cbMaxToken;
            Name = pkg.Name;
            Comment = pkg.Comment;
        }

        /// <summary>
        /// Get authentication packages.
        /// </summary>
        /// <returns>The list of authentication packages.</returns>
        public static IEnumerable<AuthenticationPackage> Get()
        {
            List<AuthenticationPackage> packages = new List<AuthenticationPackage>();
            if (SecurityNativeMethods.EnumerateSecurityPackages(out int count,
                out IntPtr ppPackageInfo) == SecStatusCode.Success)
            {
                try
                {
                    int size = Marshal.SizeOf(typeof(SecPkgInfo));
                    for (int i = 0; i < count; ++i)
                    {
                        SecPkgInfo pkg = (SecPkgInfo)Marshal.PtrToStructure(ppPackageInfo + i * size, typeof(SecPkgInfo));
                        packages.Add(new AuthenticationPackage(pkg));
                    }
                }
                finally
                {
                    SecurityNativeMethods.FreeContextBuffer(ppPackageInfo);
                }
            }
            return packages.AsReadOnly();
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
        /// <returns>The authentication package.</returns>
        public static AuthenticationPackage FromName(string package)
        {
            SecurityNativeMethods.QuerySecurityPackageInfo(package, out IntPtr package_info).CheckResult();
            try
            {
                return new AuthenticationPackage((SecPkgInfo)Marshal.PtrToStructure(package_info, typeof(SecPkgInfo)));
            }
            finally
            {
                SecurityNativeMethods.FreeContextBuffer(package_info);
            }
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
    }
}
