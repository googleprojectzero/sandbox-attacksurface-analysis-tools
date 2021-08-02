//  Copyright 2021 Google LLC. All Rights Reserved.
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
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NtApiDotNet.Win32.DirectoryService
{
    /// <summary>
    /// Class to represent a binding to a directory service.
    /// </summary>
    public sealed class DirectoryServiceBinding : IDisposable
    {
        #region Private Members
        private readonly SafeDirectoryServiceHandle _handle;

        private DirectoryServiceBinding(SafeDirectoryServiceHandle handle)
        {
            _handle = handle;
        }

        private IReadOnlyList<DirectoryServiceNameResult> GetNameResults(IntPtr ptr)
        {
            try
            {
                var results = ptr.ReadStruct<DS_NAME_RESULTW>();
                return results.rItems.ReadArray<DS_NAME_RESULT_ITEMW>(results.cItems)
                    .Select(DirectoryServiceNameResult.Create).ToList().AsReadOnly();
            }
            finally
            {
                DirectoryServiceNativeMethods.DsFreeNameResult(ptr);
            }
        }

        #endregion

        #region Public Methods
        /// <summary>
        /// Crack one or more names on the domain controller.
        /// </summary>
        /// <param name="flags">Flags for the cracking.</param>
        /// <param name="format_offered">Format of the names.</param>
        /// <param name="format_desired">Desired format of the names.</param>
        /// <param name="names">The list of names to crack.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The cracked names.</returns>
        public NtResult<IReadOnlyList<DirectoryServiceNameResult>> CrackNames(
            DirectoryServiceNameFlags flags,
            DirectoryServiceNameFormat format_offered,
            DirectoryServiceNameFormat format_desired,
            IEnumerable<string> names,
            bool throw_on_error)
        {
            string[] names_arr = names.ToArray();
            if (names_arr.Length == 0)
                return new List<DirectoryServiceNameResult>().AsReadOnly().CreateResult<IReadOnlyList<DirectoryServiceNameResult>>();
            return DirectoryServiceNativeMethods.DsCrackNames(_handle, flags, format_offered,
                format_desired, names_arr.Length, names_arr, out IntPtr results).CreateWin32Result(throw_on_error,
                () => GetNameResults(results));
        }

        /// <summary>
        /// Crack one or more names on the domain controller.
        /// </summary>
        /// <param name="flags">Flags for the cracking.</param>
        /// <param name="format_offered">Format of the names.</param>
        /// <param name="format_desired">Desired format of the names.</param>
        /// <param name="names">The list of names to crack.</param>
        /// <returns>The cracked names.</returns>
        public IReadOnlyList<DirectoryServiceNameResult> CrackNames(
            DirectoryServiceNameFlags flags,
            DirectoryServiceNameFormat format_offered,
            DirectoryServiceNameFormat format_desired,
            IEnumerable<string> names)
        {
            return CrackNames(flags, format_offered, format_desired, names, true).Result;
        }

        /// <summary>
        /// Crack a name on the domain controller.
        /// </summary>
        /// <param name="flags">Flags for the cracking.</param>
        /// <param name="format_offered">Format of the name.</param>
        /// <param name="format_desired">Desired format of the name.</param>
        /// <param name="name">The name to crack.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The cracked name.</returns>
        public NtResult<DirectoryServiceNameResult> CrackName(
            DirectoryServiceNameFlags flags,
            DirectoryServiceNameFormat format_offered,
            DirectoryServiceNameFormat format_desired,
            string name,
            bool throw_on_error
            )
        {
            return CrackNames(flags, format_offered,
                format_desired, new string[] { name }, 
                throw_on_error).Map(l => l.First());
        }

        /// <summary>
        /// Crack a name on the domain controller.
        /// </summary>
        /// <param name="flags">Flags for the cracking.</param>
        /// <param name="format_offered">Format of the name.</param>
        /// <param name="format_desired">Desired format of the name.</param>
        /// <param name="name">The name to crack.</param>
        /// <returns>The cracked name.</returns>
        public DirectoryServiceNameResult CrackName(
            DirectoryServiceNameFlags flags,
            DirectoryServiceNameFormat format_offered,
            DirectoryServiceNameFormat format_desired,
            string name
            )
        {
            return CrackName(flags, format_offered,
                format_desired, name, true).Result;
        }

        /// <summary>
        /// Get naming contexts for domain.
        /// </summary>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The naming contexts.</returns>
        public NtResult<IReadOnlyList<string>> GetNamingContextNames(bool throw_on_error)
        {
            return CrackNames(DirectoryServiceNameFlags.None,
                unchecked((DirectoryServiceNameFormat)0xFFFFFFF6), DirectoryServiceNameFormat.FQDN1779,
                new[] { "A" }, throw_on_error).Map<IReadOnlyList<string>>(
                s => s.Select(m => m.Name).ToList().AsReadOnly());
        }

        /// <summary>
        /// Get naming contexts for domain.
        /// </summary>
        /// <returns>The naming contexts.</returns>
        public IReadOnlyList<string> GetNamingContextNames()
        {
            return GetNamingContextNames(true).Result;
        }

        #endregion

        #region Static Members
        /// <summary>
        /// Bind to a directory service.
        /// </summary>
        /// <param name="domain_controller_name">The name of the domain controller. Can be null.</param>
        /// <param name="dns_domain_name">The DNS domain name.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The directory service binding.</returns>
        public static NtResult<DirectoryServiceBinding> Bind(string domain_controller_name, string dns_domain_name, bool throw_on_error)
        {
            return DirectoryServiceNativeMethods.DsBind(domain_controller_name, dns_domain_name, 
                out SafeDirectoryServiceHandle handle).CreateWin32Result(throw_on_error, () => new DirectoryServiceBinding(handle));
        }

        /// <summary>
        /// Bind to a directory service.
        /// </summary>
        /// <param name="domain_controller_name">The name of the domain controller. Can be null.</param>
        /// <param name="dns_domain_name">The DNS domain name.</param>
        /// <returns>The directory service binding.</returns>
        public static DirectoryServiceBinding Bind(string domain_controller_name, string dns_domain_name)
        {
            return Bind(domain_controller_name, dns_domain_name, true).Result;
        }

        /// <summary>
        /// Bind to the current directory service.
        /// </summary>
        /// <returns>The directory service binding.</returns>
        public static DirectoryServiceBinding Bind()
        {
            return Bind(null, null);
        }

        #endregion

        #region IDisposable Implementation
        /// <summary>
        /// Dispose the binding.
        /// </summary>
        public void Dispose()
        {
            ((IDisposable)_handle).Dispose();
        }
        #endregion
    }
}
