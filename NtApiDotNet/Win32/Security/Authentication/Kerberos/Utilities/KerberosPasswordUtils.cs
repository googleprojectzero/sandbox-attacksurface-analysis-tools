//  Copyright 2022 Google LLC. All Rights Reserved.
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
using NtApiDotNet.Win32.Security.Authentication.Logon;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authentication.Kerberos.Utilities
{
    /// <summary>
    /// Utilities to set and change Kerberos passwords.
    /// </summary>
    public static class KerberosPasswordUtils
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct KERB_CHANGEPASSWORD_REQUEST
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public UnicodeStringOut DomainName;
            public UnicodeStringOut AccountName;
            public UnicodeStringOut OldPassword;
            public UnicodeStringOut NewPassword;
            [MarshalAs(UnmanagedType.U1)]
            public bool Impersonating;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct KERB_SETPASSWORD_EX_REQUEST
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public Luid LogonId;
            public SecHandle CredentialsHandle;
            public int Flags;
            public UnicodeStringOut DomainName;
            public UnicodeStringOut AccountName;
            public UnicodeStringOut Password;
            public UnicodeStringOut ClientRealm;
            public UnicodeStringOut ClientName;
            [MarshalAs(UnmanagedType.U1)]
            public bool Impersonating;
            public UnicodeStringOut KdcAddress;
            public int KdcAddressType;
        }

        private const int DS_UNKNOWN_ADDRESS_TYPE = 0;
        private const int KERB_SETPASS_USE_LOGONID = 1;
        private const int KERB_SETPASS_USE_CREDHANDLE = 2;

        private static NtStatus DoCall<T>(LsaBufferBuilder<T> builder, bool throw_on_error) where T : new()
        {
            using (var buffer = builder.ToBuffer())
            {
                using (var handle = LsaLogonHandle.Connect(throw_on_error))
                {
                    if (!handle.IsSuccess)
                        return handle.Status;
                    using (var result = handle.Result.LsaCallAuthenticationPackage(AuthenticationPackage.KERBEROS_NAME, buffer, throw_on_error))
                    {
                        if (!result.IsSuccess)
                            return result.Status.ToNtException(throw_on_error);
                        return result.Result.Status.ToNtException(throw_on_error);
                    }
                }
            }
        }

        private static NtStatus SetPassword(KERB_PROTOCOL_MESSAGE_TYPE message_type, UserCredentials credentials, int flags, Luid logon_id, 
            SecHandle cred_handle, string client_realm, string client_name, bool impersonating, string kdc_address, int kdc_address_type, bool throw_on_error)
        {
            if (credentials is null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            var builder = new KERB_SETPASSWORD_EX_REQUEST()
            {
                MessageType = message_type,
                Flags = flags,
                LogonId = logon_id,
                CredentialsHandle = cred_handle,
                Impersonating = impersonating,
                KdcAddressType = kdc_address_type
            }.ToBuilder();

            builder.AddUnicodeString(nameof(KERB_SETPASSWORD_EX_REQUEST.AccountName), credentials.UserName);
            builder.AddUnicodeString(nameof(KERB_SETPASSWORD_EX_REQUEST.DomainName), credentials.Domain);
            builder.AddUnicodeString(nameof(KERB_SETPASSWORD_EX_REQUEST.Password), credentials.Password);
            builder.AddUnicodeString(nameof(KERB_SETPASSWORD_EX_REQUEST.ClientRealm), client_realm);
            builder.AddUnicodeString(nameof(KERB_SETPASSWORD_EX_REQUEST.ClientName), client_name);
            builder.AddUnicodeString(nameof(KERB_SETPASSWORD_EX_REQUEST.KdcAddress), kdc_address);
            return DoCall(builder, throw_on_error);
        }

        private static NtStatus RefreshSmartcardCredentials(Luid logon_id, KERB_REFRESH_SCCRED_REQUEST_FLAGS flags, 
            string credential_blob, bool throw_on_error)
        {
            var builder = new KERB_REFRESH_SCCRED_REQUEST()
            {
                MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRefreshSmartcardCredentialsMessage,
                LogonId = logon_id,
                Flags = flags
            }.ToBuilder();
            builder.AddUnicodeString(nameof(KERB_REFRESH_SCCRED_REQUEST.CredentialBlob), credential_blob);
            return DoCall(builder, throw_on_error);
        }

        /// <summary>
        /// Change a user's password.
        /// </summary>
        /// <param name="credentials">The existing user's credentials.</param>
        /// <param name="new_password">The user's new password.</param>
        /// <param name="impersonating">True if impersonating.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus ChangePassword(UserCredentials credentials, string new_password, bool impersonating, bool throw_on_error)
        {
            if(credentials is null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            var builder = new KERB_CHANGEPASSWORD_REQUEST()
            {
                MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbChangePasswordMessage,
                Impersonating = impersonating
            }.ToBuilder();

            builder.AddUnicodeString(nameof(KERB_CHANGEPASSWORD_REQUEST.AccountName), credentials.UserName);
            builder.AddUnicodeString(nameof(KERB_CHANGEPASSWORD_REQUEST.DomainName), credentials.Domain);
            builder.AddUnicodeString(nameof(KERB_CHANGEPASSWORD_REQUEST.OldPassword), credentials.Password);
            builder.AddUnicodeString(nameof(KERB_CHANGEPASSWORD_REQUEST.NewPassword), new_password);

            return DoCall(builder, throw_on_error);
        }

        /// <summary>
        /// Change a user's password.
        /// </summary>
        /// <param name="credentials">The existing user's credentials.</param>
        /// <param name="new_password">The user's new password.</param>
        /// <param name="impersonating">True if impersonating.</param>
        public static void ChangePassword(UserCredentials credentials, string new_password, bool impersonating)
        {
            ChangePassword(credentials, new_password, impersonating, true);
        }

        /// <summary>
        /// Set a user's password.
        /// </summary>
        /// <param name="credentials">The existing user's credentials.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus SetPassword(UserCredentials credentials, bool throw_on_error)
        {
            if (credentials is null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            return SetPassword(KERB_PROTOCOL_MESSAGE_TYPE.KerbSetPasswordMessage, credentials, 0, default, 
                null, null, null, false, null, 0, throw_on_error);
        }

        /// <summary>
        /// Set a user's password.
        /// </summary>
        /// <param name="credentials">The existing user's credentials.</param>
        public static void SetPassword(UserCredentials credentials)
        {
            SetPassword(credentials, true);
        }

        /// <summary>
        /// Set a user's password.
        /// </summary>
        /// <param name="credentials">The existing user's credentials.</param>
        /// <param name="logon_id">The logon ID to use for the call.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus SetPassword(UserCredentials credentials, Luid logon_id, bool throw_on_error)
        {
            if (credentials is null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            return SetPassword(KERB_PROTOCOL_MESSAGE_TYPE.KerbSetPasswordMessage, credentials, 
                KERB_SETPASS_USE_LOGONID, logon_id, null, null, null, false, null, 0, throw_on_error);
        }

        /// <summary>
        /// Set a user's password.
        /// </summary>
        /// <param name="credentials">The existing user's credentials.</param>
        /// <param name="logon_id">The logon ID to use for the call.</param>
        public static void SetPassword(UserCredentials credentials, Luid logon_id)
        {
            SetPassword(credentials, logon_id, true);
        }

        /// <summary>
        /// Set a user's password.
        /// </summary>
        /// <param name="credentials">The existing user's credentials.</param>
        /// <param name="credential_handle">The credential handle to use for the call.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus SetPassword(UserCredentials credentials, CredentialHandle credential_handle, bool throw_on_error)
        {
            if (credentials is null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (credential_handle is null)
            {
                throw new ArgumentNullException(nameof(credential_handle));
            }

            return SetPassword(KERB_PROTOCOL_MESSAGE_TYPE.KerbSetPasswordMessage, credentials,
                KERB_SETPASS_USE_CREDHANDLE, default, credential_handle.CredHandle, null, null, false, null, 0, throw_on_error);
        }

        /// <summary>
        /// Set a user's password.
        /// </summary>
        /// <param name="credentials">The existing user's credentials.</param>
        /// <param name="credential_handle">The credential handle to use for the call.</param>
        public static void SetPassword(UserCredentials credentials, CredentialHandle credential_handle)
        {
            SetPassword(credentials, credential_handle, true);
        }

        /// <summary>
        /// Set a user's password.
        /// </summary>
        /// <param name="credentials">The existing user's credentials.</param>
        /// <param name="client_name">The client name.</param>
        /// <param name="client_realm">The client realm.</param>
        /// <param name="impersonating">Whether the caller is impersonating.</param>
        /// <param name="kdc_address">The KDC address to change.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus SetPassword(UserCredentials credentials, string client_name, string client_realm, 
            bool impersonating,string kdc_address, bool throw_on_error)
        {
            if (credentials is null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            return SetPassword(KERB_PROTOCOL_MESSAGE_TYPE.KerbSetPasswordExMessage, credentials, 0, default,
                null, client_realm, client_name, impersonating, kdc_address, DS_UNKNOWN_ADDRESS_TYPE, throw_on_error);
        }

        /// <summary>
        /// Set a user's password.
        /// </summary>
        /// <param name="credentials">The existing user's credentials.</param>
        /// <param name="client_name">The client name.</param>
        /// <param name="client_realm">The client realm.</param>
        /// <param name="impersonating">Whether the caller is impersonating.</param>
        /// <param name="kdc_address">The KDC address to change.</param>
        public static void SetPassword(UserCredentials credentials, string client_name, string client_realm, 
            bool impersonating, string kdc_address)
        {
            SetPassword(credentials, client_name, client_realm, impersonating, kdc_address, true);
        }

        /// <summary>
        /// Set a user's password.
        /// </summary>
        /// <param name="credentials">The existing user's credentials.</param>
        /// <param name="client_name">The client name.</param>
        /// <param name="client_realm">The client realm.</param>
        /// <param name="impersonating">Whether the caller is impersonating.</param>
        /// <param name="kdc_address">The KDC address to change.</param>
        /// <param name="logon_id">The logon ID to use for the call.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus SetPassword(UserCredentials credentials, Luid logon_id, string client_name, string client_realm,
            bool impersonating, string kdc_address, bool throw_on_error)
        {
            if (credentials is null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            return SetPassword(KERB_PROTOCOL_MESSAGE_TYPE.KerbSetPasswordExMessage, credentials, KERB_SETPASS_USE_LOGONID, logon_id,
                null, client_realm, client_name, impersonating, kdc_address, DS_UNKNOWN_ADDRESS_TYPE, throw_on_error);
        }

        /// <summary>
        /// Set a user's password.
        /// </summary>
        /// <param name="credentials">The existing user's credentials.</param>
        /// <param name="client_name">The client name.</param>
        /// <param name="client_realm">The client realm.</param>
        /// <param name="impersonating">Whether the caller is impersonating.</param>
        /// <param name="kdc_address">The KDC address to change.</param>
        /// <param name="logon_id">The logon ID to use for the call.</param>
        public static void SetPassword(UserCredentials credentials, Luid logon_id, string client_name, string client_realm,
            bool impersonating, string kdc_address)
        {
            SetPassword(credentials, logon_id, client_name, client_realm, impersonating, kdc_address, true);
        }

        /// <summary>
        /// Set a user's password.
        /// </summary>
        /// <param name="credentials">The existing user's credentials.</param>
        /// <param name="client_name">The client name.</param>
        /// <param name="client_realm">The client realm.</param>
        /// <param name="impersonating">Whether the caller is impersonating.</param>
        /// <param name="kdc_address">The KDC address to change.</param>
        /// <param name="credential_handle">The credential handle to use for the call.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus SetPassword(UserCredentials credentials, CredentialHandle credential_handle, string client_name, string client_realm,
            bool impersonating, string kdc_address, bool throw_on_error)
        {
            if (credentials is null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (credential_handle is null)
            {
                throw new ArgumentNullException(nameof(credential_handle));
            }

            return SetPassword(KERB_PROTOCOL_MESSAGE_TYPE.KerbSetPasswordExMessage, credentials, KERB_SETPASS_USE_CREDHANDLE, default,
                credential_handle.CredHandle, client_realm, client_name, impersonating, kdc_address, DS_UNKNOWN_ADDRESS_TYPE, throw_on_error);
        }

        /// <summary>
        /// Set a user's password.
        /// </summary>
        /// <param name="credentials">The existing user's credentials.</param>
        /// <param name="client_name">The client name.</param>
        /// <param name="client_realm">The client realm.</param>
        /// <param name="impersonating">Whether the caller is impersonating.</param>
        /// <param name="kdc_address">The KDC address to change.</param>
        /// <param name="credential_handle">The credential handle to use for the call.</param>
        public static void SetPassword(UserCredentials credentials, CredentialHandle credential_handle, string client_name, string client_realm,
            bool impersonating, string kdc_address)
        {
            SetPassword(credentials, credential_handle, client_name, client_realm, impersonating, kdc_address, true);
        }

        /// <summary>
        /// Release smartcard credentials.
        /// </summary>
        /// <param name="logon_id">The logon ID to use for the call.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus ReleaseSmartcardCredentials(Luid logon_id, bool throw_on_error)
        {
            return RefreshSmartcardCredentials(logon_id, KERB_REFRESH_SCCRED_REQUEST_FLAGS.KERB_REFRESH_SCCRED_RELEASE, null, throw_on_error);
        }

        /// <summary>
        /// Release smartcard credentials.
        /// </summary>
        /// <param name="logon_id">The logon ID to use for the call.</param>
        public static void ReleaseSmartcardCredentials(Luid logon_id)
        {
            ReleaseSmartcardCredentials(logon_id, true);
        }

        /// <summary>
        /// Tickle the smart card credentials.
        /// </summary>
        /// <param name="credential_blob">The credentials to tickle.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        /// <exception cref="ArgumentNullException">Throw on null argument.</exception>
        public static NtStatus TickleSmartcardCredentials(string credential_blob, bool throw_on_error)
        {
            if (credential_blob is null)
            {
                throw new ArgumentNullException(nameof(credential_blob));
            }

            return RefreshSmartcardCredentials(default, KERB_REFRESH_SCCRED_REQUEST_FLAGS.KERB_REFRESH_SCCRED_GETTGT, 
                credential_blob, throw_on_error);
        }

        /// <summary>
        /// Tickle the smart card credentials.
        /// </summary>
        /// <param name="credential_blob">The credentials to tickle.</param>
        /// <exception cref="ArgumentNullException">Throw on null argument.</exception>
        public static void TickleSmartcardCredentials(string credential_blob)
        {
            TickleSmartcardCredentials(credential_blob, true);
        }
    }
}
