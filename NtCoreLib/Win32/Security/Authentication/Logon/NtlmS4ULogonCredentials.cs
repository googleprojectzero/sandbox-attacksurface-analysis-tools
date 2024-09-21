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
    public enum NtlmS4ULogonFlags
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        None = 0,
        [SDKName("MSV1_0_S4U_LOGON_FLAG_CHECK_LOGONHOURS")]
        CheckLogonHours = 2
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }

    /// <summary>
    /// Class to represent a MSV1_0_S4U_LOGON structure.
    /// </summary>
    public sealed class NtlmS4ULogonCredentials : ILsaLogonCredentials
    {
        /// <summary>
        /// Flags for the logon.
        /// </summary>
        public NtlmS4ULogonFlags Flags { get; set; }

        /// <summary>
        /// The client user principal name.
        /// </summary>
        public string UserPrincipalName { get; set; }

        /// <summary>
        /// The client domain name.
        /// </summary>
        public string DomainName { get; set; }

        string ILsaLogonCredentials.AuthenticationPackage => AuthenticationPackage.NTLM_NAME;

        SafeBuffer ILsaLogonCredentials.ToBuffer(DisposableList list)
        {
            if (UserPrincipalName is null)
            {
                throw new ArgumentNullException(nameof(UserPrincipalName));
            }

            if (DomainName is null)
            {
                throw new ArgumentNullException(nameof(DomainName));
            }

            var builder = new MSV1_0_S4U_LOGON()
            {
                MessageType = MSV1_0_LOGON_SUBMIT_TYPE.MsV1_0S4ULogon,
                Flags = (int)Flags
            }.ToBuilder();

            builder.AddUnicodeString(nameof(MSV1_0_S4U_LOGON.UserPrincipalName), UserPrincipalName);
            builder.AddUnicodeString(nameof(MSV1_0_S4U_LOGON.DomainName), DomainName);
            return builder.ToBuffer();
        }
    }
}
