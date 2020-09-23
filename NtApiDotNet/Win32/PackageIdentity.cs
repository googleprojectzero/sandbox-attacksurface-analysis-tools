//  Copyright 2019 Google Inc. All Rights Reserved.
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
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NtApiDotNet.Win32
{
    /// <summary>
    /// APPX Package Architecture.
    /// </summary>
    public enum PackageArchitecture
    {
        /// <summary>
        /// X86
        /// </summary>
        X86 = 0,
        /// <summary>
        /// ARM
        /// </summary>
        ARM = 5,
        /// <summary>
        /// X64
        /// </summary>
        X64 = 9,
        /// <summary>
        /// Neutral
        /// </summary>
        Neutral = 11,
        /// <summary>
        /// ARM64
        /// </summary>
        ARM64 = 12,
    }

    /// <summary>
    /// APPX Package Origin.
    /// </summary>
    public enum PackageOrigin
    {
        /// <summary>
        /// Unknown origin.
        /// </summary>
        Unknown,
        /// <summary>
        /// Unsigned.
        /// </summary>
        Unsigned,
        /// <summary>
        /// Inbox.
        /// </summary>
        Inbox,
        /// <summary>
        /// Store.
        /// </summary>
        Store,
        /// <summary>
        /// Developer unsigned.
        /// </summary>
        DeveloperUnsigned,
        /// <summary>
        /// Developer signed.
        /// </summary>
        DeveloperSigned,
        /// <summary>
        /// Line-of-business.
        /// </summary>
        LineOfBusiness
    }

    /// <summary>
    /// Class which represents an AppContainer package identity.
    /// </summary>
    public class PackageIdentity
    {
        private static string GetString(IntPtr p)
        {
            if (p == IntPtr.Zero)
            {
                return string.Empty;
            }
            return Marshal.PtrToStringUni(p);
        }

        /// <summary>
        /// Process architecture.
        /// </summary>
        public PackageArchitecture ProcessorArchitecture { get; }

        /// <summary>
        /// Package version.
        /// </summary>
        public Version Version { get; }

        /// <summary>
        /// Package family name.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Publisher (not always available).
        /// </summary>
        public string Publisher { get; }

        /// <summary>
        /// Resource ID.
        /// </summary>
        public string ResourceId { get; }

        /// <summary>
        /// Published ID.
        /// </summary>
        public string PublisherId { get; }

        /// <summary>
        /// Full package name.
        /// </summary>
        public string FullName { get; }

        /// <summary>
        /// Package origin.
        /// </summary>
        public PackageOrigin Origin { get; }

        /// <summary>
        /// Package family name.
        /// </summary>
        public string FamilyName { get; }

        /// <summary>
        /// Package install path.
        /// </summary>
        public string Path { get; }

        /// <summary>
        /// The list of application model IDs.
        /// </summary>
        public IEnumerable<string> ApplicationModelIds { get; }

        private PackageIdentity(string package_full_name, PACKAGE_ID package_id, PackageOrigin origin, string path, IEnumerable<string> appids)
        {
            FullName = package_full_name;
            ProcessorArchitecture = (PackageArchitecture)package_id.processorArchitecture;
            Name = GetString(package_id.name);
            Publisher = GetString(package_id.publisher);
            PublisherId = GetString(package_id.publisherId);
            ResourceId = GetString(package_id.resourceId);
            Version = new Version(package_id.version.Major, package_id.version.Minor, package_id.version.Build, package_id.version.Revision);
            Origin = origin;
            Path = path;
            FamilyName = $"{Name}_{PublisherId}";
            ApplicationModelIds = appids ?? new string[0];
        }

        /// <summary>
        /// Get the GetStagedPackageOrigin method as a delegate. It's supposed to be exposed by kernel32,
        /// but actually doesn't seem to be.
        /// </summary>
        /// <returns></returns>
        private static GetStagedPackageOrigin FindDelegate()
        {
            GetStagedPackageOrigin result = null;
            SafeLoadLibraryHandle kernel_base = SafeLoadLibraryHandle.GetModuleHandleNoThrow("kernelbase");
            if (!kernel_base.IsInvalid)
            {
                result = kernel_base.GetFunctionPointer<GetStagedPackageOrigin>(false);
            }
            if (result != null)
            {
                return result;
            }
            SafeLoadLibraryHandle kernel32 = SafeLoadLibraryHandle.GetModuleHandle("kernel32");
            return kernel32.GetFunctionPointer<GetStagedPackageOrigin>();
        }

        private static GetStagedPackageOrigin _get_staged_package_origin = FindDelegate();

        private delegate Win32Error GetPackagePathFunc<T>(T name, ref int length, StringBuilder path);

        private static string[] ReadStrings(SafeBuffer buffer, int count)
        {
            IntPtr[] ptrs = new IntPtr[count];

            buffer.ReadArray(0, ptrs, 0, count);

            return ptrs.Select(p => GetString(p)).ToArray();
        }

        private static NtResult<string[]> GetAppIds(string full_name)
        {
            var result = Win32NativeMethods.OpenPackageInfoByFullName(full_name, 0, out IntPtr package_info);
            if (result != Win32Error.SUCCESS)
                return result.CreateResultFromDosError<string[]>(false);
            try
            {
                int length = 0;
                result = Win32NativeMethods.GetPackageApplicationIds(package_info, ref length, SafeHGlobalBuffer.Null, out int count);
                if (result != Win32Error.ERROR_INSUFFICIENT_BUFFER)
                {
                    return result.CreateResultFromDosError<string[]>(false);
                }
                using (var buffer = new SafeHGlobalBuffer(length))
                {
                    return Win32NativeMethods.GetPackageApplicationIds(package_info, ref length, buffer, out count)
                        .CreateWin32Result(false, () => ReadStrings(buffer, count));
                }
            }
            finally
            {
                if (package_info != IntPtr.Zero)
                    Win32NativeMethods.ClosePackageInfo(package_info);
            }
        }

        private static NtResult<string> GetPackagePath<T>(T name, GetPackagePathFunc<T> func, bool throw_on_error)
        {
            int length = 0;
            var result = func(name, ref length, null);
            if (result != Win32Error.ERROR_INSUFFICIENT_BUFFER)
            {
                return result.CreateResultFromDosError<string>(throw_on_error);
            }

            var builder = new StringBuilder(length);
            result = func(name, ref length, builder);
            if (result != Win32Error.SUCCESS)
            {
                return result.CreateResultFromDosError<string>(throw_on_error);
            }

            return builder.ToString().CreateResult();
        }

        /// <summary>
        /// Create from a package full name.
        /// </summary>
        /// <param name="package_full_name">The package full name.</param>
        /// <param name="full_information">Query for full information (needs to be installed for the current user).</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The package identity.</returns>
        public static NtResult<PackageIdentity> CreateFromFullName(string package_full_name, bool full_information, bool throw_on_error)
        {
            PackageFlags flags = full_information ? PackageFlags.Full : PackageFlags.Basic;

            var staged_path = GetPackagePath(package_full_name, Win32NativeMethods.GetStagedPackagePathByFullName, throw_on_error);
            if (!staged_path.IsSuccess)
                return staged_path.Cast<PackageIdentity>();

            Win32Error result = _get_staged_package_origin(package_full_name, out PackageOrigin origin);
            if (result != Win32Error.SUCCESS)
            {
                return result.CreateResultFromDosError<PackageIdentity>(throw_on_error);
            }

            int length = 0;
            result = Win32NativeMethods.PackageIdFromFullName(package_full_name, flags, ref length, SafeHGlobalBuffer.Null);
            if (result != Win32Error.ERROR_INSUFFICIENT_BUFFER)
            {
                return result.CreateResultFromDosError<PackageIdentity>(throw_on_error);
            }

            using (var buffer = new SafeStructureInOutBuffer<PACKAGE_ID>(length, false))
            {
                result = Win32NativeMethods.PackageIdFromFullName(package_full_name, flags, ref length, buffer);
                if (result != Win32Error.SUCCESS)
                {
                    return result.CreateResultFromDosError<PackageIdentity>(throw_on_error);
                }

                return new PackageIdentity(package_full_name, buffer.Result, origin, staged_path.Result, 
                    GetAppIds(package_full_name).GetResultOrDefault()).CreateResult();
            }
        }

        /// <summary>
        /// Create from a package full name.
        /// </summary>
        /// <param name="package_full_name">The package full name.</param>
        /// <param name="full_information">Query for full information (needs to be installed for the current user).</param>
        /// <returns>The package identity.</returns>
        public static PackageIdentity CreateFromFullName(string package_full_name, bool full_information)
        {
            return CreateFromFullName(package_full_name, full_information, true).Result;
        }

        /// <summary>
        /// Create from a token.
        /// </summary>
        /// <param name="token">The AppContainer token.</param>
        /// <param name="full_information">Query for full information (needs to be installed for the current user).</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The package identity.</returns>
        public static NtResult<PackageIdentity> CreateFromToken(NtToken token, bool full_information, bool throw_on_error)
        {
            var full_name = GetPackagePath(token.Handle, Win32NativeMethods.GetPackageFullNameFromToken, throw_on_error);
            if (!full_name.IsSuccess)
                return full_name.Cast<PackageIdentity>();
            return CreateFromFullName(full_name.Result, full_information, throw_on_error);
        }

        /// <summary>
        /// Create from a token.
        /// </summary>
        /// <param name="token">The AppContainer token.</param>
        /// <param name="full_information">Query for full information (needs to be installed for the current user).</param>
        /// <returns>The package identity.</returns>
        public static PackageIdentity CreateFromToken(NtToken token, bool full_information)
        {
            return CreateFromToken(token, full_information, true).Result;
        }
    }
}
