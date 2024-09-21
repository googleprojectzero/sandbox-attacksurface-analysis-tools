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

using NtCoreLib.Utilities.Collections;
using NtCoreLib.Utilities.Memory;
using NtCoreLib.Win32.Security.Interop;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NtCoreLib.Win32.Security.Credential;

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
            
            if (key != null && length > 0)
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
        using var buffer = credential.ToBuffer();
        return SecurityNativeMethods.CredMarshalCredential(credential.CredType, buffer,
            out SafeCredBuffer cred_string).CreateWin32Result(throw_on_error, () =>
        {
            using (cred_string)
            {
                return cred_string.ReadNulTerminatedUnicodeStringUnsafe();
            }
        });
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

    /// <summary>
    /// Marshal a certificate to a string.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <returns>The marshalled certificate.</returns>
    public static string MarshalCertificate(X509Certificate certificate)
    {
        return MarshalCredential(new CredentialMarshalCertificate(certificate));
    }

    /// <summary>
    /// Protect a credential EX version.
    /// </summary>
    /// <param name="flags">Flags for the protection.</param>
    /// <param name="credential">The credential to protect.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The protected credential.</returns>
    public static NtResult<string> ProtectCredentialEx(CredentialProtectFlag flags, byte[] credential, bool throw_on_error)
    {
        if (credential is null)
            throw new ArgumentNullException(nameof(credential));

        if ((credential.Length & 1) != 0)
            throw new ArgumentException("Credential must be multiple of 2.", nameof(credential));

        int length = 0;
        var error = SecurityNativeMethods.CredProtectEx(flags, credential, credential.Length / 2,
            null, ref length, out CredentialProtectionType protection_type).GetLastWin32Error();
        if (error == Win32Error.SUCCESS)
            return NtStatus.STATUS_INVALID_PARAMETER.CreateResultFromError<string>(throw_on_error);
        if (error != Win32Error.ERROR_INSUFFICIENT_BUFFER)
            return error.CreateResultFromDosError<string>(throw_on_error);

        byte[] buffer = new byte[length * 2];
        return SecurityNativeMethods.CredProtectEx(flags, credential, credential.Length / 2,
            buffer, ref length, out protection_type).CreateWin32Result(throw_on_error, 
            () => Encoding.Unicode.GetString(buffer).TrimEnd('\0'));
    }

    /// <summary>
    /// Protect a credential EX version.
    /// </summary>
    /// <param name="flags">Flags for the protection.</param>
    /// <param name="credential">The credential to protect.</param>
    /// <returns>The protected credential.</returns>
    public static string ProtectCredentialEx(CredentialProtectFlag flags, byte[] credential)
    {
        return ProtectCredentialEx(flags, credential, true).Result;
    }

    /// <summary>
    /// Protect a credential EX version.
    /// </summary>
    /// <param name="flags">Flags for the protection.</param>
    /// <param name="credential">The credential to protect.</param>
    /// <returns>The protected credential.</returns>
    public static string ProtectCredentialEx(CredentialProtectFlag flags, string credential)
    {
        return ProtectCredentialEx(flags, Encoding.Unicode.GetBytes(credential));
    }

    /// <summary>
    /// Protect a credential.
    /// </summary>
    /// <param name="as_self">True to protect as self.</param>
    /// <param name="credential">The credential to protect.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The protected credential.</returns>
    public static NtResult<string> ProtectCredential(bool as_self, string credential, bool throw_on_error)
    {
        if (credential is null)
            throw new ArgumentNullException(nameof(credential));

        int length = 0;
        var error = SecurityNativeMethods.CredProtect(as_self, credential, credential.Length / 2,
            null, ref length, out CredentialProtectionType protection_type).GetLastWin32Error();
        if (error == Win32Error.SUCCESS)
            return NtStatus.STATUS_INVALID_PARAMETER.CreateResultFromError<string>(throw_on_error);
        if (error != Win32Error.ERROR_INSUFFICIENT_BUFFER)
            return error.CreateResultFromDosError<string>(throw_on_error);

        byte[] buffer = new byte[length * 2];
        return SecurityNativeMethods.CredProtect(as_self, credential, credential.Length / 2,
            buffer, ref length, out protection_type).CreateWin32Result(throw_on_error, 
            () => Encoding.Unicode.GetString(buffer).TrimEnd('\0'));
    }

    /// <summary>
    /// Protect a credential.
    /// </summary>
    /// <param name="as_self">True to protect as self.</param>
    /// <param name="credential">The credential to protect.</param>
    /// <returns>The protected credential.</returns>
    public static string ProtectCredential(bool as_self, string credential)
    {
        return ProtectCredential(as_self, credential, true).Result;
    }

    /// <summary>
    /// Unprotect a credential.
    /// </summary>
    /// <param name="as_self">True to unprotect as self.</param>
    /// <param name="credential">The credential to unprotect.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The unprotected credential.</returns>
    public static NtResult<string> UnprotectCredential(bool as_self, string credential, bool throw_on_error)
    {
        if (credential is null)
            throw new ArgumentNullException(nameof(credential));

        int length = 0;
        var error = SecurityNativeMethods.CredUnprotect(as_self, credential, credential.Length,
            null, ref length).GetLastWin32Error();
        if (error == Win32Error.SUCCESS)
            return NtStatus.STATUS_INVALID_PARAMETER.CreateResultFromError<string>(throw_on_error);
        if (error != Win32Error.ERROR_INSUFFICIENT_BUFFER)
            return error.CreateResultFromDosError<string>(throw_on_error);

        byte[] buffer = new byte[length * 2];
        return SecurityNativeMethods.CredUnprotect(as_self, credential, credential.Length / 2,
            buffer, ref length).CreateWin32Result(throw_on_error,
            () => Encoding.Unicode.GetString(buffer).TrimEnd('\0'));
    }

    /// <summary>
    /// Unprotect a credential.
    /// </summary>
    /// <param name="as_self">True to unprotect as self.</param>
    /// <param name="credential">The credential to unprotect.</param>
    /// <returns>The unprotected credential.</returns>
    public static string UnprotectCredential(bool as_self, string credential)
    {
        return UnprotectCredential(as_self, credential, true).Result;
    }

    /// <summary>
    /// Unprotect a credential.
    /// </summary>
    /// <param name="flags">Flags for the unprotect.</param>
    /// <param name="credential">The credential to unprotect.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The unprotected credential.</returns>
    public static NtResult<byte[]> UnprotectCredentialEx(CredentialUnprotectFlag flags, string credential, bool throw_on_error)
    {
        if (credential is null)
            throw new ArgumentNullException(nameof(credential));

        int length = 0;
        var error = SecurityNativeMethods.CredUnprotectEx(flags, credential, credential.Length,
            null, ref length).GetLastWin32Error();
        if (error == Win32Error.SUCCESS)
            return NtStatus.STATUS_INVALID_PARAMETER.CreateResultFromError<byte[]>(throw_on_error);
        if (error != Win32Error.ERROR_INSUFFICIENT_BUFFER)
            return error.CreateResultFromDosError<byte[]>(throw_on_error);

        byte[] buffer = new byte[length * 2];
        return SecurityNativeMethods.CredUnprotectEx(flags, credential, credential.Length / 2,
            buffer, ref length).CreateWin32Result(throw_on_error,
            () => buffer);
    }

    /// <summary>
    /// Unprotect a credential.
    /// </summary>
    /// <param name="flags">Flags for the unprotect.</param>
    /// <param name="credential">The credential to unprotect.</param>
    /// <returns>The unprotected credential.</returns>
    public static byte[] UnprotectCredentialEx(CredentialUnprotectFlag flags, string credential)
    {
        return UnprotectCredentialEx(flags, credential, true).Result;
    }

    /// <summary>
    /// Get the credential protection type of an encrypted credential.
    /// </summary>
    /// <param name="credential">The credentials.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The protection type.</returns>
    public static NtResult<CredentialProtectionType> GetCredentialProtectionType(string credential, bool throw_on_error)
    {
        return SecurityNativeMethods.CredIsProtected(credential, out CredentialProtectionType protection_type)
            .CreateWin32Result(throw_on_error, () => protection_type);
    }

    /// <summary>
    /// Get the credential protection type of an encrypted credential.
    /// </summary>
    /// <param name="credential">The credentials.</param>
    /// <returns>The protection type.</returns>
    public static CredentialProtectionType GetCredentialProtectionType(string credential)
    {
        return GetCredentialProtectionType(credential, true).Result;
    }

    /// <summary>
    /// Write a credential to the manager.
    /// </summary>
    /// <param name="credential">The credential to write.</param>
    /// <param name="flags">The flags.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The status of the write.</returns>
    public static NtStatus SetCredential(Credential credential, CredentialWriteFlags flags, bool throw_on_error)
    {
        using var list = new DisposableList();
        return SecurityNativeMethods.CredWrite(credential.ToCredential(list),
            flags).ToNtException(throw_on_error);
    }

    /// <summary>
    /// Write a credential to the manager.
    /// </summary>
    /// <param name="credential">The credential to write.</param>
    /// <param name="flags">The flags.</param>
    public static void SetCredential(Credential credential, CredentialWriteFlags flags = CredentialWriteFlags.None)
    {
        SetCredential(credential, flags, true);
    }

    /// <summary>
    /// Delete a credential by name.
    /// </summary>
    /// <param name="target_name">The name of the credential.</param>
    /// <param name="type">The type of credential.</param>
    /// <param name="throw_on_error">True to throw on error.</param>
    /// <returns>The status of the delete.</returns>
    public static NtStatus DeleteCredential(string target_name, CredentialType type, bool throw_on_error)
    {
        return SecurityNativeMethods.CredDelete(target_name, type, 0).ToNtException(throw_on_error);
    }

    /// <summary>
    /// Delete a credential by name.
    /// </summary>
    /// <param name="target_name">The name of the credential.</param>
    /// <param name="type">The type of credential.</param>
    public static void DeleteCredential(string target_name, CredentialType type)
    {
        DeleteCredential(target_name, type, true);
    }
}
