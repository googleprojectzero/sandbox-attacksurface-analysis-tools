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

using NtApiDotNet.Win32.Security.Native;
using System;
using System.Runtime.InteropServices;
using System.Security;

namespace NtApiDotNet.Win32.Security.Authentication.Logon
{
    /// <summary>
    /// Class to represent a KERB_INTERACTIVE_LOGON or a KERB_INTERACTIVE_UNLOCK_LOGON credential buffer.
    /// </summary>
    public sealed class KerberosInteractiveLogonCredentials : ILsaLogonCredentials, ILsaLogonCredentialsSerializable
    {
        /// <summary>
        /// The logon domain name.
        /// </summary>
        public string LogonDomainName { get; set; }
        /// <summary>
        /// The logon user name.
        /// </summary>
        public string UserName { get; set; }
        /// <summary>
        /// The logon password.
        /// </summary>
        public SecureString Password { get; set; }
        /// <summary>
        /// If specified will create a KERB_INTERACTIVE_UNLOCK_LOGON credential buffer.
        /// </summary>
        public Luid? LogonId { get; set; }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="credentials"></param>
        public KerberosInteractiveLogonCredentials(UserCredentials credentials)
        {
            if (credentials is null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            LogonDomainName = credentials.Domain;
            UserName = credentials.UserName;
            Password = credentials.Password;
        }

        private void PopulateLogon(LsaBufferBuilder<KERB_INTERACTIVE_LOGON> builder, bool relative)
        {
            builder.AddUnicodeString(nameof(KERB_INTERACTIVE_LOGON.LogonDomainName), LogonDomainName, relative);
            builder.AddUnicodeString(nameof(KERB_INTERACTIVE_LOGON.UserName), UserName, relative);
            builder.AddUnicodeString(nameof(KERB_INTERACTIVE_LOGON.Password), Password, relative);
        }

        private SafeBufferGeneric ToBuffer(bool relative)
        {
            if (LogonId.HasValue)
            {
                var builder =  new KERB_INTERACTIVE_UNLOCK_LOGON()
                {
                    LogonId = LogonId.Value
                }.ToBuilder();
                PopulateLogon(builder.GetSubBuilder(nameof(KERB_INTERACTIVE_UNLOCK_LOGON.Logon), 
                    new KERB_INTERACTIVE_LOGON() {
                    MessageType = KERB_LOGON_SUBMIT_TYPE.KerbWorkstationUnlockLogon
                }), relative);
                return builder.ToBuffer();
            }
            else
            {
                var builder = new KERB_INTERACTIVE_LOGON()
                {
                    MessageType = KERB_LOGON_SUBMIT_TYPE.KerbInteractiveLogon
                }.ToBuilder();
                PopulateLogon(builder, relative);
                return builder.ToBuffer();
            }
        }

        byte[] ILsaLogonCredentialsSerializable.ToArray()
        {
            using (var buffer = ToBuffer(true))
            {
                return buffer.ToArray();
            }
        }

        SafeBuffer ILsaLogonCredentials.ToBuffer(DisposableList list)
        {
            return ToBuffer(false);
        }
    }
}
