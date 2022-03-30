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
using System;
using System.IO;
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

        /// <summary>
        /// Change a user's password.
        /// </summary>
        /// <param name="credentials">The existing user's credentials.</param>
        /// <param name="new_password">The user's new password.</param>
        /// <param name="impersonating">True if impersonating.</param>
        /// <param name="throw_on_error">True to throw on error.</param>
        /// <returns>The NT status code.</returns>
        public static NtStatus ChangePasswordRequest(UserCredentials credentials, string new_password, bool impersonating, bool throw_on_error)
        {
            if(credentials is null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            using (var list = new DisposableList())
            {
                int total_str_size = KerberosTicketCache.CalculateLength(credentials.UserName, credentials.Domain, new_password)
                    + KerberosTicketCache.CalculateLength(credentials.Password?.Length);
                var buffer = new SafeStructureInOutBuffer<KERB_CHANGEPASSWORD_REQUEST>(total_str_size, true);

                using (var strs = buffer.Data.GetStream())
                {
                    BinaryWriter writer = new BinaryWriter(strs);
                    UnicodeStringOut username = KerberosTicketCache.MarshalString(buffer.Data, writer, credentials.UserName);
                    UnicodeStringOut domain = KerberosTicketCache.MarshalString(buffer.Data, writer, credentials.Domain);
                    UnicodeStringOut password = KerberosTicketCache.MarshalString(buffer.Data, writer, credentials.GetPasswordBytes());
                    UnicodeStringOut new_pass = KerberosTicketCache.MarshalString(buffer.Data, writer, new_password);

                    buffer.Result = new KERB_CHANGEPASSWORD_REQUEST()
                    {
                        MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbChangePasswordMessage,
                        AccountName = username,
                        DomainName = domain,
                        OldPassword = password,
                        NewPassword = new_pass,
                        Impersonating = impersonating
                    };
                }

                using (var handle = SafeLsaLogonHandle.Connect(throw_on_error))
                {
                    if (!handle.IsSuccess)
                        return handle.Status;
                    using (var result = KerberosTicketCache.CallPackage(handle.Result, buffer, throw_on_error))
                    {
                        if (!result.IsSuccess)
                            return result.Status.ToNtException(throw_on_error);
                        return result.Result.Status.ToNtException(throw_on_error);
                    }
                }
            }
        }

        /// <summary>
        /// Change a user's password.
        /// </summary>
        /// <param name="credentials">The existing user's credentials.</param>
        /// <param name="new_password">The user's new password.</param>
        /// <param name="impersonating">True if impersonating.</param>
        public static void ChangePasswordRequest(UserCredentials credentials, string new_password, bool impersonating)
        {
            ChangePasswordRequest(credentials, new_password, impersonating, true);
        }
    }
}
