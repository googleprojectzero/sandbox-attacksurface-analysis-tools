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

using NtApiDotNet.Utilities.Memory;
using NtApiDotNet.Win32.SafeHandles;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace NtApiDotNet.Win32.Security.Credential
{
    /// <summary>
    /// Class to access credential manager APIs.
    /// </summary>
    public static class CredentialManager
    {
        private static Credential ParseCredential(IntPtr ptr)
        {
            return new Credential(ptr.ReadStruct<CREDENTIAL>());
        }

        private static IEnumerable<Credential> ParseCredentials(int count, SafeCredBuffer buffer)
        {
            using (buffer)
            {
                buffer.Initialize<IntPtr>((uint)count);
                IntPtr[] ptrs = buffer.ReadArray<IntPtr>(0, count);

                return ptrs.Select(ParseCredential).ToList().AsReadOnly();
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

        /// <summary>
        /// Get a credential by name.
        /// </summary>
        /// <param name="target_name">The name of the credential.</param>
        /// <param name="type">The type of credential.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The read credential.</returns>
        public static NtResult<Credential> GetCredential(string target_name, CredentialType type, bool throw_on_error)
        {
            return SecurityNativeMethods.CredRead(target_name, type, 0, out SafeCredBuffer buffer).CreateWin32Result(throw_on_error, () => {
                using (buffer)
                {
                    return ParseCredential(buffer.DangerousGetHandle());
                }
            });
        }

        /// <summary>
        /// Get a credential by name.
        /// </summary>
        /// <param name="target_name">The name of the credential.</param>
        /// <param name="type">The type of credential.</param>
        /// <returns>The read credential.</returns>
        public static Credential GetCredential(string target_name, CredentialType type)
        {
            return GetCredential(target_name, type, true).Result;
        }

        /// <summary>
        /// Backup a user's credentials.
        /// </summary>
        /// <param name="token">The user's token.</param>
        /// <param name="key">The key for the data, typically a unicode password. Optional</param>
        /// <param name="key_encoded">True if the key is already encoded.</param>
        /// <remarks>Caller needs SeTrustedCredmanAccessPrivilege enabled.</remarks>
        public static byte[] Backup(NtToken token, byte[] key, bool key_encoded)
        {
            string target_path = Path.GetTempFileName();
            IntPtr ptr = IntPtr.Zero;
            try
            {
                int length = (key?.Length * 2) ?? 0;
                
                if (length > 0)
                {
                    ptr = Marshal.AllocHGlobal(key.Length);
                    Marshal.Copy(key, 0, ptr, key.Length);
                }
                if (!SecurityNativeMethods.CredBackupCredentials(token.Handle, target_path,
                    ptr, length, key_encoded ? 1 : 0))
                {
                    Win32Utils.GetLastWin32Error().ToNtException();
                }

                return ProtectedData.Unprotect(File.ReadAllBytes(target_path),
                    null, DataProtectionScope.CurrentUser);
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(ptr);
                }
                File.Delete(target_path);
            }
        }

        /// <summary>
        /// Marshal a credentials buffer to a string.
        /// </summary>
        /// <param name="credential">The credentials.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The marshalled credentials.</returns>
        public static NtResult<string> MarshalCredential(CredentialMarshalBase credential, bool throw_on_error)
        {
            using (var buffer = credential.ToBuffer())
            {
                return SecurityNativeMethods.CredMarshalCredential(credential.CredType, buffer, 
                    out SafeCredBuffer cred_string).CreateWin32Result(throw_on_error, () =>
                {
                    using (cred_string)
                    {
                        return cred_string.ReadNulTerminatedUnicodeStringUnsafe();
                    }
                });
            }
        }

        /// <summary>
        /// Marshal a credentials buffer to a string.
        /// </summary>
        /// <param name="credential">The credentials.</param>
        /// <returns>The marshalled credentials.</returns>
        public static string MarshalCredential(CredentialMarshalBase credential)
        {
            return MarshalCredential(credential, true).Result;
        }

        /// <summary>
        /// Unmarshal a credentials buffer from a string.
        /// </summary>
        /// <param name="credential">The marshalled credentials.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The unmarshalled credentials.</returns>
        public static NtResult<CredentialMarshalBase> UnmarshalCredential(string credential, bool throw_on_error)
        {
            return SecurityNativeMethods.CredUnmarshalCredential(credential, out CredMarshalType cred_type, 
                out SafeCredBuffer buffer).CreateWin32Result(throw_on_error, () => CredentialMarshalBase.GetCredentialBuffer(buffer, cred_type));
        }

        /// <summary>
        /// Unmarshal a credentials buffer from a string.
        /// </summary>
        /// <param name="credential">The marshalled credentials.</param>
        /// <returns>The unmarshalled credentials.</returns>
        public static CredentialMarshalBase UnmarshalCredential(string credential)
        {
            return UnmarshalCredential(credential, true).Result;
        }
    }
}
