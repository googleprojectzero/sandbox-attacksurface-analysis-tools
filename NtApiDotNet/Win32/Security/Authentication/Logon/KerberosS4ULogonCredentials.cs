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

using NtApiDotNet.Utilities.Reflection;
using NtApiDotNet.Win32.Security.Native;
using System;
using System.Runtime.InteropServices;

namespace NtApiDotNet.Win32.Security.Authentication.Logon
{
    /// <summary>
    /// Flags for the S4U logon.
    /// </summary>
    [Flags]
    public enum KerberosS4ULogonFlags
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        [SDKName("KERB_S4U_LOGON_FLAG_CHECK_LOGONHOURS")]
        CheckLogonHours = 2,
        [SDKName("KERB_S4U_LOGON_FLAG_IDENTIFY")]
        Identify = 8,
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }

    /// <summary>
    /// Class to represent a KERB_S4U_LOGON structure.
    /// </summary>
    public sealed class KerberosS4ULogonCredentials : ILsaLogonCredentials
    {
        /// <summary>
        /// Flags for the logon.
        /// </summary>
        public KerberosS4ULogonFlags Flags { get; set; }

        /// <summary>
        /// The client user principal name.
        /// </summary>
        public string ClientUpn { get; set; }

        /// <summary>
        /// The client realm.
        /// </summary>
        public string ClientRealm { get; set; }

        string ILsaLogonCredentials.AuthenticationPackage => AuthenticationPackage.KERBEROS_NAME;

        SafeBuffer ILsaLogonCredentials.ToBuffer(DisposableList list)
        {
            if (ClientUpn is null)
            {
                throw new ArgumentNullException(nameof(ClientUpn));
            }

            if (ClientRealm is null)
            {
                throw new ArgumentNullException(nameof(ClientRealm));
            }

            var builder = new KERB_S4U_LOGON()
            {
                MessageType = KERB_LOGON_SUBMIT_TYPE.KerbS4ULogon,
                Flags = (int)Flags
            }.ToBuilder();

            builder.AddUnicodeString(nameof(KERB_S4U_LOGON.ClientUpn), ClientUpn);
            builder.AddUnicodeString(nameof(KERB_S4U_LOGON.ClientRealm), ClientRealm);
            return builder.ToBuffer();
        }
    }
}
