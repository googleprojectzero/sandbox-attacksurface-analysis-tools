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
using System.Linq;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Credential
{
    /// <summary>
    /// Class to access credential manager APIs.
    /// </summary>
    public static class CredentialManager
    {
        private static IEnumerable<Credential> ParseCredentials(int count, SafeCredBuffer buffer)
        {
            using (buffer)
            {
                buffer.Initialize<IntPtr>((uint)count);
                IntPtr[] ptrs = buffer.ReadArray<IntPtr>(0, count);

                return ptrs.Select(p => (CREDENTIAL)Marshal.PtrToStructure(p, 
                    typeof(CREDENTIAL))).Select(c => new Credential(c)).ToList().AsReadOnly();
            }
        }

        /// <summary>
        /// Get credentials for user from credential manager.
        /// </summary>
        /// <param name="filter">A filter for the target name, for example DOMAIN*. If null or empty returns all credentials.</param>
        /// <param name="flags">Flags for the enumeration.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The list of credentials.</returns>
        public static NtResult<IEnumerable<Credential>> GetCredentials(string filter, CredentialEnumerateFlags flags, bool throw_on_error)
        {
            if (string.IsNullOrEmpty(filter))
            {
                filter = null;
            }
            return SecurityNativeMethods.CredEnumerate(flags.HasFlagSet(CredentialEnumerateFlags.AllCredentials) ? null : filter, flags, out int count, 
                out SafeCredBuffer buffer).CreateWin32Result(throw_on_error, () => ParseCredentials(count, buffer));
        }

        /// <summary>
        /// Get credentials for user from credential manager.
        /// </summary>
        /// <param name="filter">A filter for the target name, for example DOMAIN*. If null or empty returns all credentials.</param>
        /// <param name="flags">Flags for the enumeration.</param>
        /// <returns>The list of credentials.</returns>
        public static IEnumerable<Credential> GetCredentials(string filter, CredentialEnumerateFlags flags)
        {
            return GetCredentials(filter, flags, true).Result;
        }

        /// <summary>
        /// Get credentials for user from credential manager.
        /// </summary>
        /// <param name="filter">A filter for the target name, for example DOMAIN*. If null or empty returns all credentials.</param>
        /// <returns>The list of credentials.</returns>
        public static IEnumerable<Credential> GetCredentials(string filter)
        {
            return GetCredentials(filter, CredentialEnumerateFlags.None, true).Result;
        }

        /// <summary>
        /// Get all credentials for user from credential manager.
        /// </summary>
        /// <returns>The list of credentials.</returns>
        public static IEnumerable<Credential> GetCredentials()
        {
            return GetCredentials(null);
        }
    }
}
